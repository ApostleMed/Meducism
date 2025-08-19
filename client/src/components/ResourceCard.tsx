import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Resource } from "@shared/schema";

interface ResourceCardProps {
  resource: Resource;
}

export default function ResourceCard({ resource }: ResourceCardProps) {
  const typeColors = {
    "PDF Document": "bg-blue-50 text-primary",
    "Interactive Tool": "bg-green-50 text-healthcare-green",
    "Manifesto": "bg-pink-50 text-secondary",
    "Curriculum Guide": "bg-orange-50 text-accent",
    "Guide": "bg-blue-50 text-primary",
    "Research": "bg-green-50 text-healthcare-green",
  };

  return (
    <Card className="overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
      {resource.imageUrl && (
        <img 
          src={resource.imageUrl} 
          alt={resource.title}
          className="w-full h-48 object-cover"
        />
      )}
      <CardContent className="p-6">
        <h3 className="text-xl font-merriweather font-bold mb-3">{resource.title}</h3>
        <p className="text-gray-600 mb-4">
          {resource.description}
        </p>
        <div className="flex items-center justify-between">
          <span className={`text-sm px-3 py-1 rounded-full ${typeColors[resource.type as keyof typeof typeColors] || 'bg-gray-50 text-gray-600'}`}>
            {resource.type}
          </span>
          <Button variant="ghost" className="text-primary hover:text-secondary p-0">
            <i className="fas fa-download mr-1"></i> 
            Download
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
