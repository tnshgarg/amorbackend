const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const { Webhook } = require("svix");
const cors = require("cors");
const crypto = require("crypto");
// middleware/authenticateUser.js
const { clerkClient, verifyToken } = require("@clerk/clerk-sdk-node");

// Load environment variables
dotenv.config();

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define Schemas
const UserSchema = new mongoose.Schema({
  clerkId: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  name: { type: String },
  credits: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const SongSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clerkId: { type: String, required: true },
  songTitle: { type: String, required: true },
  loveStory: { type: String, required: true },
  lyrics: { type: String, required: true },
  sunoTaskId: { type: String, required: true },
  callbackId: { type: String, required: true },
  songUrls: [{ type: String }],
  status: {
    type: String,
    enum: ["processing", "completed", "failed"],
    default: "processing",
  },
  shareId: { type: String, unique: true, sparse: true },
  isPublic: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date },
});

const IssueSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  clerkId: { type: String },
  type: { type: String, required: true },
  description: { type: String, required: true },
  stackTrace: { type: String },
  resolved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  resolvedAt: { type: Date },
});

const PurchaseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clerkId: { type: String, required: true },
  amount: { type: Number, required: true },
  credits: { type: Number, required: true },
  paymentId: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "completed", "failed"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date },
});

// Create models
const User = mongoose.model("User", UserSchema);
const Song = mongoose.model("Song", SongSchema);
const Issue = mongoose.model("Issue", IssueSchema);
const Purchase = mongoose.model("Purchase", PurchaseSchema);

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:8080", "https://your-frontend-url.com"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Store minimal task info (just for callback handling)
const taskCallbacks = new Map();

// Authentication middleware

const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: No token" });
    }

    const token = authHeader.split(" ")[1];

    // 🔐 Clerk JWT verification (with apiKey and issuer)
    const { sub } = await verifyToken(token, {
      apiKey: process.env.CLERK_SECRET_KEY,
      issuer: process.env.CLERK_JWT_ISSUER, // typically https://<your-clerk-app>.clerk.accounts.dev
    });

    // console.log("Authenticated user ID:", JSON.stringify(obj));

    const user = await clerkClient.users.getUser(sub);

    console.log("user: ", JSON.stringify(user));

    let dbUser = await User.findOne({ clerkId: user.id });
    if (!dbUser) {
      dbUser = await User.create({
        clerkId: user.id,
        email: user.emailAddresses[0].emailAddress,
        name: `${user.firstName || ""} ${user.lastName || ""}`.trim(),
      });
    }

    req.user = dbUser;
    next();
  } catch (error) {
    console.error("Auth Error:", error);
    res.status(401).json({
      error: "Authentication failed",
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

// TEMPORARY SOLUTION FOR DEVELOPMENT ONLY - REMOVE IN PRODUCTION
// const authenticateUser = async (req, res, next) => {
//   try {
//     // Create a mock user for testing
//     req.user = {
//       _id: new mongoose.Types.ObjectId(), // Create valid ObjectId
//       clerkId: "mock_clerk_id",
//       email: "test@example.com",
//       name: "Test User",
//       credits: 10,
//     };

//     next();
//   } catch (error) {
//     return res.status(401).json({
//       error: "Authentication failed",
//       details: process.env.NODE_ENV === "development" ? error.message : null,
//     });
//   }
// };

// Helper function to log issues
const logIssue = async (userId, clerkId, type, description, stackTrace) => {
  try {
    const issue = new Issue({
      userId,
      clerkId,
      type,
      description,
      stackTrace,
    });
    await issue.save();
    console.error(`Issue logged: ${type} - ${description}`);
  } catch (err) {
    console.error("Failed to log issue:", err);
  }
};

// Middleware for error handling
const errorHandler = async (err, req, res, next) => {
  console.error(err);

  // Log error to database
  const userId = req.user ? req.user._id : null;
  const clerkId = req.user ? req.user.clerkId : null;
  await logIssue(userId, clerkId, "server_error", err.message, err.stack);

  res.status(500).json({
    error: "An unexpected error occurred",
    details: process.env.NODE_ENV === "development" ? err.message : null,
  });
};

app.post("/sync-user", authenticateUser, async (req, res) => {
  res.status(200).json({ message: "User synced", user: req.user });
});

// Clerk webhook endpoint for user events
app.post("/webhook/clerk", async (req, res) => {
  try {
    // Verify webhook signature
    const svixHeaders = {
      "svix-id": req.headers["svix-id"],
      "svix-timestamp": req.headers["svix-timestamp"],
      "svix-signature": req.headers["svix-signature"],
    };
    const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);
    const payload = wh.verify(JSON.stringify(req.body), svixHeaders);

    const { type, data } = payload;

    if (type === "user.created" || type === "user.updated") {
      // Create or update user in our database
      await User.findOneAndUpdate(
        { clerkId: data.id },
        {
          email: data.email_addresses[0].email_address,
          name: `${data.first_name || ""} ${data.last_name || ""}`.trim(),
          updatedAt: new Date(),
        },
        { upsert: true, new: true }
      );
    }

    if (type === "user.deleted") {
      // Don't actually delete the user record - just mark it as deleted
      // This preserves history and avoids foreign key issues
      await User.findOneAndUpdate(
        { clerkId: data.id },
        {
          isDeleted: true,
          updatedAt: new Date(),
        }
      );
    }

    res.status(200).json({ success: true });
  } catch (error) {
    await logIssue(
      null,
      null,
      "webhook",
      "Clerk webhook processing failed",
      error.stack
    );
    res.status(400).json({ error: "Webhook error", message: error.message });
  }
});

// Route for generating personalized song from love story
app.post("/generate-song", authenticateUser, async (req, res, next) => {
  try {
    const { loveStory, songTitle } = req.body;
    const userId = req.user._id;
    const clerkId = req.user.clerkId;

    // Validate input
    if (!loveStory) {
      return res.status(400).json({ error: "Love story is required" });
    }

    if (!songTitle) {
      return res.status(400).json({ error: "Song title is required" });
    }

    // Check if user has enough credits
    if (req.user.credits <= 0) {
      return res.status(403).json({
        error: "Insufficient credits",
        credits: req.user.credits,
      });
    }

    // Step 1: Generate lyrics using Claude AI
    const claudeResponse = await axios.post(
      "https://api.anthropic.com/v1/messages",
      {
        model: "claude-3-sonnet-20240229",
        max_tokens: 1000,
        messages: [
          {
            role: "user",
            content: `Create soul-stirring, emotionally profound song lyrics based on this love story. The lyrics should feel intensely personal and capture the essence of the relationship described:
    
    Love Story:
    ${loveStory}
    
    Craft these lyrics to:
    - Include a memorable chorus that repeats 2-3 times and contains the emotional core of the story
    - Utilize powerful imagery and sensory details specific to the relationship
    - Incorporate metaphors that elevate the emotional impact
    - Focus on authentic, raw emotion rather than clichés
    - Contain 24-30 lines total with clear verse/chorus structure
    - Include at least one striking, memorable line that captures the relationship's unique essence
    - Balance universal themes with specific details from the love story
    - Consider the emotional journey and arc of the relationship
    
    The lyrics should feel like they were written specifically for this couple, as if someone who knows them intimately crafted a song that would move them to tears.
    
    Write only the finished lyrics, without explanation, title, chords, or notations.`,
          },
        ],
      },
      {
        headers: {
          "Content-Type": "application/json",
          "x-api-key": process.env.CLAUDE_API_KEY,
          "anthropic-version": "2023-06-01",
        },
      }
    );

    // Extract lyrics from Claude's response
    const lyrics = claudeResponse.data.content[0].text.trim();

    console.log("Generated lyrics:", lyrics);

    // Generate a unique ID for callback
    const callbackId =
      Date.now().toString() + Math.random().toString(36).substring(2, 15);

    // Create a callback URL for this task
    const callbackUrl = `${process.env.API_BASE_URL}/suno-callback/${callbackId}`;

    // Store initial info in the Map
    taskCallbacks.set(callbackId, {
      userId,
      clerkId,
      lyrics,
      songUrl: null,
      status: "processing",
      created: new Date(),
    });

    // Step 2: Generate song using Suno API with the lyrics
    const sunoResponse = await axios.post(
      "https://apibox.erweima.ai/api/v1/generate",
      {
        prompt: lyrics,
        title: songTitle,
        model: "V3_5",
        customMode: true,
        instrumental: false,
        callbackUrl: callbackUrl,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.SUNO_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Suno response:", sunoResponse.data);

    const taskId = sunoResponse.data.data.taskId;

    // Store taskId in our callback map
    const taskInfo = taskCallbacks.get(callbackId);
    taskInfo.taskId = taskId;
    taskCallbacks.set(callbackId, taskInfo);

    // Create song record in database
    const song = new Song({
      userId,
      clerkId,
      songTitle,
      loveStory,
      lyrics,
      sunoTaskId: taskId,
      callbackId,
      status: "processing",
    });
    await song.save();

    // Deduct one credit from user
    await User.findByIdAndUpdate(userId, { $inc: { credits: -1 } });

    // Return both IDs for status checking
    res.json({
      taskId: taskId,
      callbackId: callbackId,
      lyrics: lyrics,
      status: "processing",
      creditsLeft: req.user.credits - 1,
      message:
        "Song generation has started. You can check status using the taskId or callbackId.",
    });
  } catch (error) {
    await logIssue(
      req.user?._id,
      req.user?.clerkId,
      "song_generation",
      "Failed to generate song",
      error.stack
    );
    next(error);
  }
});

// Callback endpoint for Suno API
app.post("/suno-callback/:callbackId", async (req, res) => {
  const { callbackId } = req.params;
  const songData = req.body;

  console.log(`Received callback for job ${callbackId}:`, songData);

  // Check if we have this callback ID
  if (!taskCallbacks.has(callbackId)) {
    return res.status(404).json({ error: "Callback ID not found" });
  }

  // Update task info
  const taskInfo = taskCallbacks.get(callbackId);
  taskInfo.status = "completed";
  taskInfo.completedAt = new Date();

  // Extract song URLs if available
  const songUrls = [];
  if (songData && songData.url) {
    taskInfo.songUrl = songData.url;
    songUrls.push(songData.url);
  }

  if (songData && songData.sunoData && Array.isArray(songData.sunoData)) {
    songData.sunoData.forEach((item) => {
      if (item.audioUrl) songUrls.push(item.audioUrl);
    });
  }

  taskCallbacks.set(callbackId, taskInfo);

  // Update song record in database
  try {
    await Song.findOneAndUpdate(
      { callbackId },
      {
        status: "completed",
        songUrls,
        completedAt: new Date(),
      }
    );
  } catch (error) {
    await logIssue(
      taskInfo.userId,
      taskInfo.clerkId,
      "callback_processing",
      "Failed to update song record on callback",
      error.stack
    );
  }

  // Acknowledge receipt of callback
  res.status(200).json({ message: "Callback received successfully" });
});

// Endpoint to check song status using Suno API directly
app.get("/song-status/:taskId", authenticateUser, async (req, res, next) => {
  try {
    const { taskId } = req.params;

    // Check if song exists in our database
    const song = await Song.findOne({ sunoTaskId: taskId });

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    // Verify song belongs to requesting user
    if (song.clerkId !== req.user.clerkId) {
      return res
        .status(403)
        .json({ error: "You don't have permission to access this song" });
    }

    // If song already completed in our DB, return that data
    if (
      song.status === "completed" &&
      song.songUrls &&
      song.songUrls.length > 0
    ) {
      return res.status(200).json({
        status: 200,
        taskId: song.sunoTaskId,
        songUrls: song.songUrls,
        lyrics: song.lyrics,
        songTitle: song.songTitle,
        completedAt: song.completedAt,
      });
    }

    // Otherwise, check status with Suno API
    const sunoResponse = await axios.get(
      `https://apibox.erweima.ai/api/v1/generate/record-info?taskId=${taskId}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.SUNO_API_KEY}`,
        },
      }
    );

    if (sunoResponse.data.code !== 200) {
      return res.status(400).json({
        error: "Invalid task ID or task not found",
        errorMessage: sunoResponse.data.msg,
      });
    }

    const songUrls = [];
    if (
      sunoResponse.data.data.response.sunoData &&
      Array.isArray(sunoResponse.data.data.response.sunoData)
    ) {
      sunoResponse.data.data.response.sunoData.forEach((item) => {
        if (item.audioUrl) songUrls.push(item.audioUrl);
      });
    }

    // Update song in database if we got URLs
    if (songUrls.length > 0) {
      await Song.findOneAndUpdate(
        { sunoTaskId: taskId },
        {
          status: "completed",
          songUrls,
          completedAt: new Date(),
        }
      );
    }

    const response = {
      status: sunoResponse.data.code,
      taskId: sunoResponse.data.data.taskId,
      songUrls,
      lyrics: song.lyrics,
      songTitle: song.songTitle,
    };

    res.status(200).json(response);
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "status_check",
      "Failed to check song status",
      error.stack
    );
    next(error);
  }
});

// Alternative endpoint to get status via callback ID
app.get(
  "/callback-status/:callbackId",
  authenticateUser,
  async (req, res, next) => {
    try {
      const { callbackId } = req.params;

      const song = await Song.findOne({ callbackId });

      if (!song) {
        return res.status(404).json({ error: "Song not found" });
      }

      // Verify song belongs to requesting user
      if (song.clerkId !== req.user.clerkId) {
        return res
          .status(403)
          .json({ error: "You don't have permission to access this song" });
      }

      // Check in-memory store as well for freshest data
      let response;
      if (taskCallbacks.has(callbackId)) {
        const taskInfo = taskCallbacks.get(callbackId);
        response = {
          status: taskInfo.status,
          createdAt: taskInfo.created,
          completedAt: taskInfo.completedAt,
          lyrics: taskInfo.lyrics,
          songUrl: taskInfo.songUrl,
          songTitle: song.songTitle,
        };
      } else {
        response = {
          status: song.status,
          createdAt: song.createdAt,
          completedAt: song.completedAt,
          lyrics: song.lyrics,
          songUrls: song.songUrls,
          songTitle: song.songTitle,
        };
      }

      res.json(response);
    } catch (error) {
      await logIssue(
        req.user._id,
        req.user.clerkId,
        "callback_status",
        "Failed to get callback status",
        error.stack
      );
      next(error);
    }
  }
);

// Get user profile and credits
app.get("/profile", authenticateUser, async (req, res) => {
  try {
    // Get song count
    const songCount = await Song.countDocuments({ userId: req.user._id });

    res.json({
      id: req.user._id,
      clerkId: req.user.clerkId,
      email: req.user.email,
      name: req.user.name,
      credits: req.user.credits,
      songCount,
      createdAt: req.user.createdAt,
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "profile",
      "Failed to get user profile",
      error.stack
    );
    next(error);
  }
});

// Get user's song history
app.get("/songs", authenticateUser, async (req, res, next) => {
  try {
    const page = Number.parseInt(req.query.page) || 1;
    const limit = Number.parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const songs = await Song.find({ userId: req.user._id })
      .select("-loveStory") // Exclude full love story for brevity
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Song.countDocuments({ userId: req.user._id });

    res.json({
      songs,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "song_history",
      "Failed to get song history",
      error.stack
    );
    next(error);
  }
});

// Get a specific song by ID
app.get("/songs/:id", authenticateUser, async (req, res, next) => {
  try {
    const song = await Song.findById(req.params.id);

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    // Verify song belongs to requesting user
    if (song.userId.toString() !== req.user._id.toString()) {
      return res
        .status(403)
        .json({ error: "You don't have permission to access this song" });
    }

    res.json(song);
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "song_details",
      "Failed to get song details",
      error.stack
    );
    next(error);
  }
});

// Create a share link for a song
app.post("/songs/:id/share", authenticateUser, async (req, res, next) => {
  try {
    const song = await Song.findById(req.params.id);

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    // Verify song belongs to requesting user
    if (song.userId.toString() !== req.user._id.toString()) {
      return res
        .status(403)
        .json({ error: "You don't have permission to share this song" });
    }

    // Generate a unique share ID if one doesn't exist
    if (!song.shareId) {
      const shareId = crypto.randomBytes(8).toString("hex");
      song.shareId = shareId;
      song.isPublic = true;
      await song.save();
    } else {
      // If already has a shareId but isPublic is false, make it public
      if (!song.isPublic) {
        song.isPublic = true;
        await song.save();
      }
    }

    res.json({
      shareId: song.shareId,
      shareUrl: `${process.env.FRONTEND_URL}/shared-song/${song.shareId}`,
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "share_song",
      "Failed to share song",
      error.stack
    );
    next(error);
  }
});

// Remove sharing for a song
app.delete("/songs/:id/share", authenticateUser, async (req, res, next) => {
  try {
    const song = await Song.findById(req.params.id);

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    // Verify song belongs to requesting user
    if (song.userId.toString() !== req.user._id.toString()) {
      return res
        .status(403)
        .json({ error: "You don't have permission to modify this song" });
    }

    // Make the song private but keep the shareId for future use
    song.isPublic = false;
    await song.save();

    res.json({
      message: "Song is no longer publicly shared",
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "unshare_song",
      "Failed to unshare song",
      error.stack
    );
    next(error);
  }
});

// Get a shared song by shareId (public endpoint, no auth required)
app.get("/shared-song/:shareId", async (req, res, next) => {
  try {
    const { shareId } = req.params;
    const song = await Song.findOne({ shareId, isPublic: true });

    if (!song) {
      return res
        .status(404)
        .json({ error: "Shared song not found or is private" });
    }

    // Return only necessary information for public viewing
    res.json({
      id: song._id,
      songTitle: song.songTitle,
      lyrics: song.lyrics,
      songUrls: song.songUrls,
      createdAt: song.createdAt,
    });
  } catch (error) {
    await logIssue(
      null,
      null,
      "shared_song",
      "Failed to get shared song",
      error.stack
    );
    next(error);
  }
});

// Report an issue
app.post("/report-issue", authenticateUser, async (req, res, next) => {
  try {
    const { type, description } = req.body;

    if (!type || !description) {
      return res
        .status(400)
        .json({ error: "Type and description are required" });
    }

    const issue = new Issue({
      userId: req.user._id,
      clerkId: req.user.clerkId,
      type,
      description,
    });

    await issue.save();

    res.status(201).json({
      message: "Issue reported successfully",
      issueId: issue._id,
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "issue_reporting",
      "Failed to report issue",
      error.stack
    );
    next(error);
  }
});

// Process a payment and add credits
app.post("/process-payment", authenticateUser, async (req, res, next) => {
  try {
    const { paymentId, amount, credits } = req.body;

    if (!paymentId || !amount || !credits) {
      return res.status(400).json({
        error: "Payment ID, amount, and credits are required",
      });
    }

    // Create a purchase record
    const purchase = new Purchase({
      userId: req.user._id,
      clerkId: req.user.clerkId,
      amount,
      credits,
      paymentId,
      status: "completed", // In a real app, this would be set after payment confirmation
      completedAt: new Date(),
    });

    await purchase.save();

    // Add credits to user account
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $inc: { credits } },
      { new: true }
    );

    res.status(201).json({
      message: `Added ${credits} credits successfully`,
      purchase: {
        id: purchase._id,
        amount,
        credits,
        status: purchase.status,
        completedAt: purchase.completedAt,
      },
      newCreditBalance: updatedUser.credits,
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "payment_processing",
      "Failed to process payment",
      error.stack
    );
    next(error);
  }
});

// Get purchase history
app.get("/purchases", authenticateUser, async (req, res, next) => {
  try {
    const page = Number.parseInt(req.query.page) || 1;
    const limit = Number.parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const purchases = await Purchase.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Purchase.countDocuments({ userId: req.user._id });

    res.json({
      purchases,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "purchase_history",
      "Failed to get purchase history",
      error.stack
    );
    next(error);
  }
});

// Add credits to user account (typically would be part of a payment system)
app.post("/add-credits", authenticateUser, async (req, res, next) => {
  try {
    const { credits } = req.body;

    if (!credits || credits <= 0 || !Number.isInteger(credits)) {
      return res.status(400).json({ error: "Valid credit amount required" });
    }

    // Update user credits
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $inc: { credits } },
      { new: true }
    );

    res.json({
      message: `Added ${credits} credits successfully`,
      newTotal: updatedUser.credits,
    });
  } catch (error) {
    await logIssue(
      req.user._id,
      req.user.clerkId,
      "add_credits",
      "Failed to add credits",
      error.stack
    );
    next(error);
  }
});

// Admin route to view all issues (would need admin authentication)
app.get("/admin/issues", async (req, res, next) => {
  // TODO: Implement proper admin authentication

  try {
    const page = Number.parseInt(req.query.page) || 1;
    const limit = Number.parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const issues = await Issue.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Issue.countDocuments();

    res.json({
      issues,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    await logIssue(
      null,
      null,
      "admin_issues",
      "Failed to get admin issues list",
      error.stack
    );
    next(error);
  }
});

// Global error handler
app.use(errorHandler);

// Server setup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
