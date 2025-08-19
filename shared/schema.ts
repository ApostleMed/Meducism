import { sql } from 'drizzle-orm';
import {
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  varchar,
  boolean,
  integer,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table for Replit Auth
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table for Replit Auth
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Blog posts
export const blogPosts = pgTable("blog_posts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  content: text("content").notNull(),
  excerpt: text("excerpt").notNull(),
  authorId: varchar("author_id").references(() => users.id).notNull(),
  category: varchar("category").notNull(),
  tags: text("tags").array(),
  imageUrl: varchar("image_url"),
  published: boolean("published").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Events
export const events = pgTable("events", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  description: text("description").notNull(),
  location: text("location"),
  isOnline: boolean("is_online").default(false),
  startDate: timestamp("start_date").notNull(),
  endDate: timestamp("end_date").notNull(),
  registrationUrl: text("registration_url"),
  imageUrl: varchar("image_url"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Discussion topics
export const discussions = pgTable("discussions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  content: text("content").notNull(),
  authorId: varchar("author_id").references(() => users.id).notNull(),
  category: varchar("category").notNull(),
  likes: integer("likes").default(0),
  replies: integer("replies").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Discussion replies
export const discussionReplies = pgTable("discussion_replies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  discussionId: varchar("discussion_id").references(() => discussions.id).notNull(),
  authorId: varchar("author_id").references(() => users.id).notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// Resources
export const resources = pgTable("resources", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  description: text("description").notNull(),
  type: varchar("type").notNull(), // PDF, Guide, Research, etc.
  downloadUrl: text("download_url"),
  imageUrl: varchar("image_url"),
  category: varchar("category").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// Newsletter subscriptions
export const newsletters = pgTable("newsletters", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique().notNull(),
  name: text("name"),
  role: varchar("role"),
  subscribed: boolean("subscribed").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

// Contact messages
export const contactMessages = pgTable("contact_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: varchar("email").notNull(),
  inquiryType: varchar("inquiry_type").notNull(),
  message: text("message").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// Schema types
export type UpsertUser = typeof users.$inferInsert;
export type User = typeof users.$inferSelect;

export type InsertBlogPost = typeof blogPosts.$inferInsert;
export type BlogPost = typeof blogPosts.$inferSelect;

export type InsertEvent = typeof events.$inferInsert;
export type Event = typeof events.$inferSelect;

export type InsertDiscussion = typeof discussions.$inferInsert;
export type Discussion = typeof discussions.$inferSelect;

export type InsertDiscussionReply = typeof discussionReplies.$inferInsert;
export type DiscussionReply = typeof discussionReplies.$inferSelect;

export type InsertResource = typeof resources.$inferInsert;
export type Resource = typeof resources.$inferSelect;

export type InsertNewsletter = typeof newsletters.$inferInsert;
export type Newsletter = typeof newsletters.$inferSelect;

export type InsertContactMessage = typeof contactMessages.$inferInsert;
export type ContactMessage = typeof contactMessages.$inferSelect;

// Insert schemas
export const insertBlogPostSchema = createInsertSchema(blogPosts).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertEventSchema = createInsertSchema(events).omit({
  id: true,
  createdAt: true,
});

export const insertDiscussionSchema = createInsertSchema(discussions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  likes: true,
  replies: true,
});

export const insertDiscussionReplySchema = createInsertSchema(discussionReplies).omit({
  id: true,
  createdAt: true,
});

export const insertResourceSchema = createInsertSchema(resources).omit({
  id: true,
  createdAt: true,
});

export const insertNewsletterSchema = createInsertSchema(newsletters).omit({
  id: true,
  createdAt: true,
  subscribed: true,
});

export const insertContactMessageSchema = createInsertSchema(contactMessages).omit({
  id: true,
  createdAt: true,
});
