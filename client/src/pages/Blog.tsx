import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import BlogPost from "@/components/BlogPost";
import SearchBar from "@/components/SearchBar";
import { Button } from "@/components/ui/button";

export default function Blog() {
  const [searchQuery, setSearchQuery] = useState("");

  const { data: blogPosts, isLoading } = useQuery({
    queryKey: ["/api/blog"],
  });

  const { data: searchResults, isLoading: isSearching } = useQuery({
    queryKey: ["/api/blog/search", searchQuery],
    enabled: !!searchQuery,
  });

  const displayPosts = searchQuery ? searchResults : blogPosts;

  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            Meducism Blog
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            Insights, research, and perspectives on implementing Meducist principles in healthcare and education.
          </p>
        </div>
      </section>

      {/* Search Bar */}
      <section className="py-12 bg-light-grey">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex gap-4">
            <div className="flex-1">
              <SearchBar
                placeholder="Search blog posts..."
                value={searchQuery}
                onChange={setSearchQuery}
              />
            </div>
            <Button 
              onClick={() => setSearchQuery("")}
              variant="outline"
            >
              Clear
            </Button>
          </div>
        </div>
      </section>

      {/* Blog Posts */}
      <section className="py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          {isLoading || isSearching ? (
            <div className="space-y-6">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="bg-white rounded-xl overflow-hidden shadow-lg animate-pulse">
                  <div className="w-full h-40 bg-gray-200"></div>
                  <div className="p-6 space-y-2">
                    <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                    <div className="h-6 bg-gray-200 rounded w-3/4"></div>
                    <div className="h-4 bg-gray-200 rounded w-full"></div>
                    <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                  </div>
                </div>
              ))}
            </div>
          ) : (displayPosts && Array.isArray(displayPosts) && displayPosts.length === 0) ? (
            <div className="text-center py-12">
              <div className="w-24 h-24 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-6">
                <i className="fas fa-blog text-gray-400 text-3xl"></i>
              </div>
              <h3 className="text-2xl font-merriweather font-bold text-gray-500 mb-4">
                No blog posts found
              </h3>
              <p className="text-gray-400">
                Try adjusting your search criteria or check back later for new posts.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {displayPosts && Array.isArray(displayPosts) && displayPosts.map((post: any) => (
                <BlogPost key={post.id} post={post} />
              ))}
            </div>
          )}

          {/* Default Blog Posts for Demo */}
          {!displayPosts && !isLoading && (
            <div className="space-y-6">
              <BlogPost
                post={{
                  id: "1",
                  title: "Building Compassionate Healthcare Leaders Through Meducism",
                  excerpt: "Exploring how Meducist principles transform traditional medical education to create more empathetic and ethically-grounded healthcare professionals...",
                  content: "Full article content here...",
                  authorId: "1",
                  category: "Education",
                  tags: ["education", "leadership", "compassion"],
                  imageUrl: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                  published: true,
                  createdAt: new Date('2024-03-10'),
                  updatedAt: new Date('2024-03-10')
                }}
              />
              <BlogPost
                post={{
                  id: "2",
                  title: "Navigating Ethical Dilemmas with Meducist Principles",
                  excerpt: "Real-world case studies demonstrating how the four core values of Meducism guide ethical decision-making in complex healthcare scenarios...",
                  content: "Full article content here...",
                  authorId: "2",
                  category: "Ethics",
                  tags: ["ethics", "decision-making", "case-studies"],
                  imageUrl: "https://images.unsplash.com/photo-1582750433449-648ed127bb54?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                  published: true,
                  createdAt: new Date('2024-03-07'),
                  updatedAt: new Date('2024-03-07')
                }}
              />
              <BlogPost
                post={{
                  id: "3",
                  title: "Global Implementation: Meducism Success Stories",
                  excerpt: "Highlighting successful implementations of Meducist principles in healthcare systems across different cultures and economic contexts...",
                  content: "Full article content here...",
                  authorId: "3",
                  category: "Community",
                  tags: ["global-health", "implementation", "success-stories"],
                  imageUrl: "https://images.unsplash.com/photo-1559757175-0eb30cd8c063?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                  published: true,
                  createdAt: new Date('2024-03-03'),
                  updatedAt: new Date('2024-03-03')
                }}
              />
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
