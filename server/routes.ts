import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { 
  insertBlogPostSchema,
  insertEventSchema,
  insertDiscussionSchema,
  insertDiscussionReplySchema,
  insertResourceSchema,
  insertNewsletterSchema,
  insertContactMessageSchema 
} from "@shared/schema";

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Blog routes
  app.get('/api/blog', async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
      const posts = await storage.getBlogPosts(limit);
      res.json(posts);
    } catch (error) {
      console.error("Error fetching blog posts:", error);
      res.status(500).json({ message: "Failed to fetch blog posts" });
    }
  });

  app.get('/api/blog/search', async (req, res) => {
    try {
      const query = req.query.q as string;
      if (!query) {
        return res.status(400).json({ message: "Search query is required" });
      }
      const posts = await storage.searchBlogPosts(query);
      res.json(posts);
    } catch (error) {
      console.error("Error searching blog posts:", error);
      res.status(500).json({ message: "Failed to search blog posts" });
    }
  });

  app.get('/api/blog/:id', async (req, res) => {
    try {
      const post = await storage.getBlogPost(req.params.id);
      if (!post) {
        return res.status(404).json({ message: "Blog post not found" });
      }
      res.json(post);
    } catch (error) {
      console.error("Error fetching blog post:", error);
      res.status(500).json({ message: "Failed to fetch blog post" });
    }
  });

  app.post('/api/blog', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const postData = insertBlogPostSchema.parse({
        ...req.body,
        authorId: userId,
      });
      const post = await storage.createBlogPost(postData);
      res.status(201).json(post);
    } catch (error) {
      console.error("Error creating blog post:", error);
      res.status(500).json({ message: "Failed to create blog post" });
    }
  });

  // Event routes
  app.get('/api/events', async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
      const events = await storage.getEvents(limit);
      res.json(events);
    } catch (error) {
      console.error("Error fetching events:", error);
      res.status(500).json({ message: "Failed to fetch events" });
    }
  });

  app.get('/api/events/:id', async (req, res) => {
    try {
      const event = await storage.getEvent(req.params.id);
      if (!event) {
        return res.status(404).json({ message: "Event not found" });
      }
      res.json(event);
    } catch (error) {
      console.error("Error fetching event:", error);
      res.status(500).json({ message: "Failed to fetch event" });
    }
  });

  app.post('/api/events', isAuthenticated, async (req, res) => {
    try {
      const eventData = insertEventSchema.parse(req.body);
      const event = await storage.createEvent(eventData);
      res.status(201).json(event);
    } catch (error) {
      console.error("Error creating event:", error);
      res.status(500).json({ message: "Failed to create event" });
    }
  });

  // Discussion routes
  app.get('/api/discussions', async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
      const discussions = await storage.getDiscussions(limit);
      res.json(discussions);
    } catch (error) {
      console.error("Error fetching discussions:", error);
      res.status(500).json({ message: "Failed to fetch discussions" });
    }
  });

  app.get('/api/discussions/:id', async (req, res) => {
    try {
      const discussion = await storage.getDiscussion(req.params.id);
      if (!discussion) {
        return res.status(404).json({ message: "Discussion not found" });
      }
      res.json(discussion);
    } catch (error) {
      console.error("Error fetching discussion:", error);
      res.status(500).json({ message: "Failed to fetch discussion" });
    }
  });

  app.post('/api/discussions', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const discussionData = insertDiscussionSchema.parse({
        ...req.body,
        authorId: userId,
      });
      const discussion = await storage.createDiscussion(discussionData);
      res.status(201).json(discussion);
    } catch (error) {
      console.error("Error creating discussion:", error);
      res.status(500).json({ message: "Failed to create discussion" });
    }
  });

  app.get('/api/discussions/:id/replies', async (req, res) => {
    try {
      const replies = await storage.getDiscussionReplies(req.params.id);
      res.json(replies);
    } catch (error) {
      console.error("Error fetching discussion replies:", error);
      res.status(500).json({ message: "Failed to fetch discussion replies" });
    }
  });

  app.post('/api/discussions/:id/replies', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const replyData = insertDiscussionReplySchema.parse({
        ...req.body,
        discussionId: req.params.id,
        authorId: userId,
      });
      const reply = await storage.createDiscussionReply(replyData);
      res.status(201).json(reply);
    } catch (error) {
      console.error("Error creating discussion reply:", error);
      res.status(500).json({ message: "Failed to create discussion reply" });
    }
  });

  app.post('/api/discussions/:id/like', isAuthenticated, async (req, res) => {
    try {
      await storage.likeDiscussion(req.params.id);
      res.json({ message: "Discussion liked successfully" });
    } catch (error) {
      console.error("Error liking discussion:", error);
      res.status(500).json({ message: "Failed to like discussion" });
    }
  });

  // Resource routes
  app.get('/api/resources', async (req, res) => {
    try {
      const category = req.query.category as string;
      const resources = await storage.getResources(category);
      res.json(resources);
    } catch (error) {
      console.error("Error fetching resources:", error);
      res.status(500).json({ message: "Failed to fetch resources" });
    }
  });

  app.get('/api/resources/search', async (req, res) => {
    try {
      const query = req.query.q as string;
      const category = req.query.category as string;
      if (!query) {
        return res.status(400).json({ message: "Search query is required" });
      }
      const resources = await storage.searchResources(query, category);
      res.json(resources);
    } catch (error) {
      console.error("Error searching resources:", error);
      res.status(500).json({ message: "Failed to search resources" });
    }
  });

  app.get('/api/resources/:id', async (req, res) => {
    try {
      const resource = await storage.getResource(req.params.id);
      if (!resource) {
        return res.status(404).json({ message: "Resource not found" });
      }
      res.json(resource);
    } catch (error) {
      console.error("Error fetching resource:", error);
      res.status(500).json({ message: "Failed to fetch resource" });
    }
  });

  app.post('/api/resources', isAuthenticated, async (req, res) => {
    try {
      const resourceData = insertResourceSchema.parse(req.body);
      const resource = await storage.createResource(resourceData);
      res.status(201).json(resource);
    } catch (error) {
      console.error("Error creating resource:", error);
      res.status(500).json({ message: "Failed to create resource" });
    }
  });

  // Newsletter route
  app.post('/api/newsletter', async (req, res) => {
    try {
      const newsletterData = insertNewsletterSchema.parse(req.body);
      const subscription = await storage.subscribeNewsletter(newsletterData);
      res.status(201).json(subscription);
    } catch (error) {
      console.error("Error subscribing to newsletter:", error);
      res.status(500).json({ message: "Failed to subscribe to newsletter" });
    }
  });

  // Contact route
  app.post('/api/contact', async (req, res) => {
    try {
      const contactData = insertContactMessageSchema.parse(req.body);
      const message = await storage.createContactMessage(contactData);
      res.status(201).json(message);
    } catch (error) {
      console.error("Error creating contact message:", error);
      res.status(500).json({ message: "Failed to send contact message" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
