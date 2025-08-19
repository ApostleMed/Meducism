import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import ResourceCard from "@/components/ResourceCard";
import SearchBar from "@/components/SearchBar";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export default function Resources() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");

  const { data: resources, isLoading } = useQuery({
    queryKey: ["/api/resources", selectedCategory],
  });

  const { data: searchResults, isLoading: isSearching } = useQuery({
    queryKey: ["/api/resources/search", searchQuery, selectedCategory],
    enabled: !!searchQuery,
  });

  const displayResources = searchQuery ? searchResults : resources;

  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            Academic Resources
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            Comprehensive resources for understanding and implementing Meducism philosophy and practices.
          </p>
        </div>
      </section>

      {/* Search and Filter */}
      <section className="py-12 bg-light-grey">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-xl p-8 shadow-lg">
            <h3 className="text-2xl font-merriweather font-bold mb-6 text-center">Search Resources</h3>
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <SearchBar
                  placeholder="Search resources..."
                  value={searchQuery}
                  onChange={setSearchQuery}
                />
              </div>
              <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                <SelectTrigger className="w-full md:w-48">
                  <SelectValue placeholder="All Categories" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All Categories</SelectItem>
                  <SelectItem value="manifesto">Manifestos</SelectItem>
                  <SelectItem value="guide">Guides</SelectItem>
                  <SelectItem value="research">Research</SelectItem>
                  <SelectItem value="tool">Tools</SelectItem>
                  <SelectItem value="curriculum">Curriculum</SelectItem>
                </SelectContent>
              </Select>
              <Button 
                onClick={() => {
                  setSearchQuery("");
                  setSelectedCategory("");
                }}
                variant="outline"
              >
                Clear
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Resources Grid */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {isLoading || isSearching ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="bg-white rounded-xl shadow-lg p-6 animate-pulse">
                  <div className="w-full h-48 bg-gray-200 rounded mb-4"></div>
                  <div className="h-6 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded mb-2"></div>
                  <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                </div>
              ))}
            </div>
          ) : (displayResources && Array.isArray(displayResources) && displayResources.length === 0) ? (
            <div className="text-center py-12">
              <div className="w-24 h-24 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-6">
                <i className="fas fa-search text-gray-400 text-3xl"></i>
              </div>
              <h3 className="text-2xl font-merriweather font-bold text-gray-500 mb-4">
                No resources found
              </h3>
              <p className="text-gray-400">
                Try adjusting your search criteria or browse all resources.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {displayResources && Array.isArray(displayResources) && displayResources.map((resource: any) => (
                <ResourceCard key={resource.id} resource={resource} />
              ))}
            </div>
          )}

          {/* Default Resources for Demo */}
          {!displayResources && !isLoading && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              <ResourceCard
                resource={{
                  id: "1",
                  title: "Core Aspects & Sub-Values",
                  description: "Comprehensive framework detailing the four core aspects of Meducism and their evaluation criteria.",
                  type: "PDF Document",
                  category: "guide",
                  imageUrl: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
              <ResourceCard
                resource={{
                  id: "2",
                  title: "Daily Practice Sheet",
                  description: "Self-assessment tools for daily practice evaluation based on Meducist principles and values.",
                  type: "Interactive Tool",
                  category: "tool",
                  imageUrl: "https://images.unsplash.com/photo-1576091160550-2173dba999ef?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
              <ResourceCard
                resource={{
                  id: "3",
                  title: "Manifesto of Meducism",
                  description: "The foundational document outlining the philosophical principles and vision for humanity's future.",
                  type: "Manifesto",
                  category: "manifesto",
                  imageUrl: "https://images.unsplash.com/photo-1582750433449-648ed127bb54?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
              <ResourceCard
                resource={{
                  id: "4",
                  title: "School of Meducism",
                  description: "Educational framework and curriculum for implementing Meducist principles in academic settings.",
                  type: "Curriculum Guide",
                  category: "curriculum",
                  imageUrl: "https://images.unsplash.com/photo-1576091160550-2173dba999ef?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
              <ResourceCard
                resource={{
                  id: "5",
                  title: "Implementation Guide",
                  description: "Practical strategies for implementing Meducist principles in healthcare organizations and communities.",
                  type: "Guide",
                  category: "guide",
                  imageUrl: "https://images.unsplash.com/photo-1559757175-0eb30cd8c063?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
              <ResourceCard
                resource={{
                  id: "6",
                  title: "Research Papers",
                  description: "Collection of peer-reviewed research supporting Meducist philosophy and its practical applications.",
                  type: "Research",
                  category: "research",
                  imageUrl: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=250",
                  downloadUrl: "#",
                  createdAt: new Date()
                }}
              />
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
