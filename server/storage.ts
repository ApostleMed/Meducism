import {
  users,
  blogPosts,
  events,
  discussions,
  discussionReplies,
  resources,
  newsletters,
  contactMessages,
  type User,
  type UpsertUser,
  type BlogPost,
  type InsertBlogPost,
  type Event,
  type InsertEvent,
  type Discussion,
  type InsertDiscussion,
  type DiscussionReply,
  type InsertDiscussionReply,
  type Resource,
  type InsertResource,
  type Newsletter,
  type InsertNewsletter,
  type ContactMessage,
  type InsertContactMessage,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, ilike, or, and, sql } from "drizzle-orm";

export interface IStorage {
  // User operations (required for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;

  // Blog operations
  getBlogPosts(limit?: number): Promise<BlogPost[]>;
  getBlogPost(id: string): Promise<BlogPost | undefined>;
  createBlogPost(post: InsertBlogPost): Promise<BlogPost>;
  searchBlogPosts(query: string): Promise<BlogPost[]>;

  // Event operations
  getEvents(limit?: number): Promise<Event[]>;
  getEvent(id: string): Promise<Event | undefined>;
  createEvent(event: InsertEvent): Promise<Event>;

  // Discussion operations
  getDiscussions(limit?: number): Promise<Discussion[]>;
  getDiscussion(id: string): Promise<Discussion | undefined>;
  createDiscussion(discussion: InsertDiscussion): Promise<Discussion>;
  getDiscussionReplies(discussionId: string): Promise<DiscussionReply[]>;
  createDiscussionReply(reply: InsertDiscussionReply): Promise<DiscussionReply>;
  likeDiscussion(discussionId: string): Promise<void>;

  // Resource operations
  getResources(category?: string): Promise<Resource[]>;
  getResource(id: string): Promise<Resource | undefined>;
  createResource(resource: InsertResource): Promise<Resource>;
  searchResources(query: string, category?: string): Promise<Resource[]>;

  // Newsletter operations
  subscribeNewsletter(newsletter: InsertNewsletter): Promise<Newsletter>;

  // Contact operations
  createContactMessage(message: InsertContactMessage): Promise<ContactMessage>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  // Blog operations
  async getBlogPosts(limit = 10): Promise<BlogPost[]> {
    return await db
      .select()
      .from(blogPosts)
      .where(eq(blogPosts.published, true))
      .orderBy(desc(blogPosts.createdAt))
      .limit(limit);
  }

  async getBlogPost(id: string): Promise<BlogPost | undefined> {
    const [post] = await db.select().from(blogPosts).where(eq(blogPosts.id, id));
    return post;
  }

  async createBlogPost(post: InsertBlogPost): Promise<BlogPost> {
    const [newPost] = await db.insert(blogPosts).values(post).returning();
    return newPost;
  }

  async searchBlogPosts(query: string): Promise<BlogPost[]> {
    return await db
      .select()
      .from(blogPosts)
      .where(
        and(
          eq(blogPosts.published, true),
          or(
            ilike(blogPosts.title, `%${query}%`),
            ilike(blogPosts.content, `%${query}%`),
            ilike(blogPosts.excerpt, `%${query}%`)
          )
        )
      )
      .orderBy(desc(blogPosts.createdAt));
  }

  // Event operations
  async getEvents(limit = 10): Promise<Event[]> {
    return await db
      .select()
      .from(events)
      .orderBy(desc(events.startDate))
      .limit(limit);
  }

  async getEvent(id: string): Promise<Event | undefined> {
    const [event] = await db.select().from(events).where(eq(events.id, id));
    return event;
  }

  async createEvent(event: InsertEvent): Promise<Event> {
    const [newEvent] = await db.insert(events).values(event).returning();
    return newEvent;
  }

  // Discussion operations
  async getDiscussions(limit = 10): Promise<Discussion[]> {
    return await db
      .select()
      .from(discussions)
      .orderBy(desc(discussions.updatedAt))
      .limit(limit);
  }

  async getDiscussion(id: string): Promise<Discussion | undefined> {
    const [discussion] = await db
      .select()
      .from(discussions)
      .where(eq(discussions.id, id));
    return discussion;
  }

  async createDiscussion(discussion: InsertDiscussion): Promise<Discussion> {
    const [newDiscussion] = await db
      .insert(discussions)
      .values(discussion)
      .returning();
    return newDiscussion;
  }

  async getDiscussionReplies(discussionId: string): Promise<DiscussionReply[]> {
    return await db
      .select()
      .from(discussionReplies)
      .where(eq(discussionReplies.discussionId, discussionId))
      .orderBy(desc(discussionReplies.createdAt));
  }

  async createDiscussionReply(reply: InsertDiscussionReply): Promise<DiscussionReply> {
    const [newReply] = await db
      .insert(discussionReplies)
      .values(reply)
      .returning();

    // Update reply count
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)` })
      .from(discussionReplies)
      .where(eq(discussionReplies.discussionId, reply.discussionId));
    
    await db
      .update(discussions)
      .set({ replies: count })
      .where(eq(discussions.id, reply.discussionId));

    return newReply;
  }

  async likeDiscussion(discussionId: string): Promise<void> {
    await db
      .update(discussions)
      .set({ likes: sql`${discussions.likes} + 1` })
      .where(eq(discussions.id, discussionId));
  }

  // Resource operations
  async getResources(category?: string): Promise<Resource[]> {
    const query = db.select().from(resources);
    if (category) {
      query.where(eq(resources.category, category));
    }
    return await query.orderBy(desc(resources.createdAt));
  }

  async getResource(id: string): Promise<Resource | undefined> {
    const [resource] = await db.select().from(resources).where(eq(resources.id, id));
    return resource;
  }

  async createResource(resource: InsertResource): Promise<Resource> {
    const [newResource] = await db.insert(resources).values(resource).returning();
    return newResource;
  }

  async searchResources(query: string, category?: string): Promise<Resource[]> {
    let whereCondition = or(
      ilike(resources.title, `%${query}%`),
      ilike(resources.description, `%${query}%`)
    );

    if (category) {
      whereCondition = and(whereCondition, eq(resources.category, category));
    }

    return await db
      .select()
      .from(resources)
      .where(whereCondition)
      .orderBy(desc(resources.createdAt));
  }

  // Newsletter operations
  async subscribeNewsletter(newsletter: InsertNewsletter): Promise<Newsletter> {
    const [subscription] = await db
      .insert(newsletters)
      .values(newsletter)
      .onConflictDoUpdate({
        target: newsletters.email,
        set: { subscribed: true },
      })
      .returning();
    return subscription;
  }

  // Contact operations
  async createContactMessage(message: InsertContactMessage): Promise<ContactMessage> {
    const [newMessage] = await db
      .insert(contactMessages)
      .values(message)
      .returning();
    return newMessage;
  }
}

export const storage = new DatabaseStorage();
