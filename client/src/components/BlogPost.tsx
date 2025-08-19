import { Card, CardContent } from "@/components/ui/card";
import type { BlogPost } from "@shared/schema";

interface BlogPostProps {
  post: BlogPost;
}

export default function BlogPost({ post }: BlogPostProps) {
  const categoryColors = {
    Education: "bg-blue-50 text-primary",
    Ethics: "bg-pink-50 text-secondary",
    Community: "bg-green-50 text-healthcare-green",
    Research: "bg-orange-50 text-accent",
  };

  return (
    <Card className="overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
      {post.imageUrl && (
        <img 
          src={post.imageUrl} 
          alt={post.title}
          className="w-full h-40 object-cover"
        />
      )}
      <CardContent className="p-6">
        <div className="flex items-center mb-2">
          <span className={`text-sm px-2 py-1 rounded ${categoryColors[post.category as keyof typeof categoryColors] || 'bg-gray-50 text-gray-600'}`}>
            {post.category}
          </span>
          <span className="text-sm text-gray-500 ml-3">
            {post.createdAt ? new Date(post.createdAt).toLocaleDateString() : 'No date'}
          </span>
        </div>
        <h3 className="text-xl font-merriweather font-bold mb-3">
          {post.title}
        </h3>
        <p className="text-gray-600 mb-4">
          {post.excerpt}
        </p>
        <div className="flex items-center justify-between">
          {post.tags && (
            <div className="flex gap-2">
              {post.tags.slice(0, 3).map((tag, index) => (
                <span key={index} className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                  #{tag}
                </span>
              ))}
            </div>
          )}
          <a href="#" className="text-primary hover:text-secondary font-semibold">
            Read More <i className="fas fa-arrow-right ml-1"></i>
          </a>
        </div>
      </CardContent>
    </Card>
  );
}
