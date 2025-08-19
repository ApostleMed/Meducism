# Meducism Platform

## Overview

Meducism is a full-stack web application that serves as a digital platform for the Meducism philosophy - a moral framework treating healthcare knowledge, ethical conduct, and self-care as universal human duties. The platform provides a comprehensive community space with educational resources, blog content, discussion forums, events management, and user authentication. Built as a modern React application with Express.js backend, it enables users to explore Meducism principles, access academic resources, participate in community discussions, and engage with events and educational content.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript for type safety and modern development practices
- **Routing**: Wouter for lightweight client-side routing with conditional rendering based on authentication state
- **UI Components**: Shadcn/ui component library built on Radix UI primitives for accessible, customizable components
- **Styling**: Tailwind CSS with custom healthcare-themed color scheme and CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state management, caching, and data synchronization
- **Forms**: React Hook Form with Zod validation for type-safe form handling
- **Build Tool**: Vite for fast development and optimized production builds

### Backend Architecture
- **Runtime**: Node.js with Express.js framework for RESTful API development
- **Database ORM**: Drizzle ORM with PostgreSQL for type-safe database operations and schema management
- **Authentication**: Replit Auth integration using OpenID Connect with Passport.js strategy
- **Session Management**: Express sessions with PostgreSQL storage for persistent user sessions
- **File Structure**: Monorepo structure with shared schema and types between client and server

### Database Design
- **Database**: PostgreSQL with Neon serverless for scalable cloud hosting
- **Schema Management**: Drizzle Kit for database migrations and schema synchronization
- **Core Tables**: Users, blog posts, events, discussions, discussion replies, resources, newsletters, contact messages, and sessions
- **Data Relationships**: Proper foreign key relationships between users and content (posts, discussions, events)

### Authentication & Authorization
- **Provider**: Replit Auth using OpenID Connect protocol for seamless integration
- **Session Storage**: PostgreSQL-backed sessions with configurable TTL (time-to-live)
- **Security**: HTTP-only cookies, secure flags, and CSRF protection
- **User Management**: Automatic user creation/updates with profile information sync

### API Architecture
- **Design Pattern**: RESTful API with resource-based endpoints
- **Data Validation**: Zod schemas for request/response validation shared between client and server
- **Error Handling**: Centralized error handling with proper HTTP status codes
- **Middleware**: Authentication checks, request logging, and JSON parsing

### Content Management
- **Blog System**: Full CRUD operations for blog posts with categories, tags, and search functionality
- **Events Management**: Event creation and listing with date/time handling and location support
- **Discussion Forums**: Threaded discussions with reply system for community engagement
- **Resource Library**: Academic resource management with categorization and search capabilities

## External Dependencies

### Core Framework Dependencies
- **@neondatabase/serverless**: Neon PostgreSQL serverless driver for database connectivity
- **drizzle-orm**: TypeScript ORM for database operations and query building
- **@tanstack/react-query**: Server state management and caching solution
- **express**: Node.js web framework for API development
- **passport**: Authentication middleware with OpenID Connect strategy

### UI and Styling Dependencies
- **@radix-ui/***: Comprehensive set of accessible UI primitives for component development
- **tailwindcss**: Utility-first CSS framework for responsive design
- **react-hook-form**: Performant form library with minimal re-renders
- **@hookform/resolvers**: Validation resolvers for form validation integration

### Development and Build Tools
- **vite**: Fast build tool and development server with hot module replacement
- **typescript**: Static type checking for enhanced developer experience
- **esbuild**: Fast JavaScript bundler for production builds
- **tsx**: TypeScript execution environment for server development

### Authentication and Session Management
- **openid-client**: OpenID Connect client for Replit Auth integration
- **express-session**: Session middleware for Express.js
- **connect-pg-simple**: PostgreSQL session store for persistent sessions

### File Upload and Storage
- **@google-cloud/storage**: Google Cloud Storage integration for file uploads
- **@uppy/***: File upload components and AWS S3 integration for media handling

### Utility Libraries
- **zod**: Schema validation for TypeScript with runtime type checking
- **memoizee**: Function memoization for performance optimization
- **wouter**: Lightweight routing library for React applications
- **class-variance-authority**: Utility for creating variant-based component APIs