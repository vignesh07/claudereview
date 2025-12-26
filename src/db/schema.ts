import { pgTable, text, integer, timestamp, boolean } from 'drizzle-orm/pg-core';

// Users table (from GitHub OAuth)
export const users = pgTable('users', {
  id: text('id').primaryKey(), // nanoid
  githubId: text('github_id').unique().notNull(),
  githubUsername: text('github_username').notNull(),
  githubAvatarUrl: text('github_avatar_url'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// Sessions table (stores encrypted session data)
export const sessions = pgTable('sessions', {
  id: text('id').primaryKey(), // short nanoid for URLs
  userId: text('user_id').references(() => users.id), // nullable for anonymous uploads
  title: text('title').notNull(),
  messageCount: integer('message_count').notNull(),
  toolCount: integer('tool_count').notNull(),
  durationSeconds: integer('duration_seconds').notNull(),
  visibility: text('visibility').notNull().$type<'public' | 'private'>(),
  encryptedBlob: text('encrypted_blob').notNull(), // base64 encoded
  iv: text('iv').notNull(), // initialization vector
  salt: text('salt'), // for private sessions (password key derivation)
  ownerKey: text('owner_key'), // encryption key for owner viewing (only stored for authenticated uploads)
  viewCount: integer('view_count').default(0).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at'), // optional expiration
});

// API Keys for CLI authentication
export const apiKeys = pgTable('api_keys', {
  id: text('id').primaryKey(), // nanoid
  userId: text('user_id').references(() => users.id).notNull(),
  keyHash: text('key_hash').notNull(), // hashed API key
  name: text('name').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  lastUsedAt: timestamp('last_used_at'),
});

// Type exports
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;
