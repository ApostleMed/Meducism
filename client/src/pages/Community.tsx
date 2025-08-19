import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export default function Community() {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  const [newDiscussion, setNewDiscussion] = useState({
    title: "",
    content: "",
    category: "general"
  });

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, authLoading, toast]);

  const { data: discussions, isLoading } = useQuery({
    queryKey: ["/api/discussions"],
    enabled: isAuthenticated,
  });

  const createDiscussionMutation = useMutation({
    mutationFn: async (data: typeof newDiscussion) => {
      await apiRequest("POST", "/api/discussions", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/discussions"] });
      setNewDiscussion({ title: "", content: "", category: "general" });
      toast({
        title: "Success",
        description: "Discussion created successfully!",
      });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to create discussion. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleSubmitDiscussion = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDiscussion.title.trim() || !newDiscussion.content.trim()) {
      toast({
        title: "Validation Error",
        description: "Please fill in all fields.",
        variant: "destructive",
      });
      return;
    }
    createDiscussionMutation.mutate(newDiscussion);
  };

  if (authLoading) {
    return (
      <div className="pt-16 min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            Community Hub
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            Connect with fellow Meducists worldwide, share knowledge, and participate in meaningful discussions about healthcare ethics and philosophy.
          </p>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Discussion Forums */}
          <div className="lg:col-span-2">
            <Card className="shadow-lg">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-2xl font-merriweather">Recent Discussions</CardTitle>
                  <Button
                    onClick={() => document.getElementById('new-discussion')?.scrollIntoView({ behavior: 'smooth' })}
                    className="bg-primary text-white hover:bg-primary/90"
                  >
                    Start Discussion
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-6">
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="border-l-4 border-gray-200 pl-6 py-4 bg-light-grey rounded-r-lg animate-pulse">
                        <div className="flex items-center mb-2">
                          <div className="w-10 h-10 bg-gray-300 rounded-full mr-3"></div>
                          <div>
                            <div className="h-4 bg-gray-300 rounded w-32 mb-1"></div>
                            <div className="h-3 bg-gray-300 rounded w-24"></div>
                          </div>
                        </div>
                        <div className="h-5 bg-gray-300 rounded w-3/4 mb-2"></div>
                        <div className="h-4 bg-gray-300 rounded w-full mb-3"></div>
                        <div className="flex space-x-4">
                          <div className="h-3 bg-gray-300 rounded w-20"></div>
                          <div className="h-3 bg-gray-300 rounded w-20"></div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (discussions && Array.isArray(discussions) && discussions.length === 0) ? (
                  <div className="text-center py-12">
                    <div className="w-24 h-24 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-6">
                      <i className="fas fa-comments text-gray-400 text-3xl"></i>
                    </div>
                    <h3 className="text-2xl font-merriweather font-bold text-gray-500 mb-4">
                      No discussions yet
                    </h3>
                    <p className="text-gray-400 mb-6">
                      Be the first to start a discussion in our community!
                    </p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {discussions && Array.isArray(discussions) && discussions.map((discussion: any) => (
                      <div key={discussion.id} className="border-l-4 border-primary pl-6 py-4 bg-light-grey rounded-r-lg">
                        <div className="flex items-center mb-2">
                          <div className="w-10 h-10 bg-primary rounded-full flex items-center justify-center text-white font-semibold mr-3">
                            {discussion.authorId?.charAt(0)?.toUpperCase() || 'A'}
                          </div>
                          <div>
                            <h4 className="font-semibold">Community Member</h4>
                            <span className="text-sm text-gray-500">
                              {new Date(discussion.createdAt).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        <h5 className="text-lg font-semibold mb-2">{discussion.title}</h5>
                        <p className="text-gray-600 mb-3">{discussion.content.substring(0, 150)}...</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-500">
                          <span><i className="fas fa-comment mr-1"></i> {discussion.replies} replies</span>
                          <span><i className="fas fa-heart mr-1"></i> {discussion.likes} likes</span>
                          <span><i className="fas fa-tag mr-1"></i> {discussion.category}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* New Discussion Form */}
            <Card className="shadow-lg mt-8" id="new-discussion">
              <CardHeader>
                <CardTitle className="text-xl font-merriweather">Start a New Discussion</CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmitDiscussion} className="space-y-4">
                  <div>
                    <Input
                      placeholder="Discussion title..."
                      value={newDiscussion.title}
                      onChange={(e) => setNewDiscussion(prev => ({ ...prev, title: e.target.value }))}
                      className="w-full"
                    />
                  </div>
                  <div>
                    <Select
                      value={newDiscussion.category}
                      onValueChange={(value) => setNewDiscussion(prev => ({ ...prev, category: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="general">General Discussion</SelectItem>
                        <SelectItem value="ethics">Ethics</SelectItem>
                        <SelectItem value="education">Education</SelectItem>
                        <SelectItem value="self-care">Self-Care</SelectItem>
                        <SelectItem value="implementation">Implementation</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Textarea
                      placeholder="Share your thoughts, questions, or experiences..."
                      value={newDiscussion.content}
                      onChange={(e) => setNewDiscussion(prev => ({ ...prev, content: e.target.value }))}
                      rows={4}
                      className="w-full"
                    />
                  </div>
                  <Button 
                    type="submit" 
                    className="w-full bg-primary text-white hover:bg-primary/90"
                    disabled={createDiscussionMutation.isPending}
                  >
                    {createDiscussionMutation.isPending ? "Creating..." : "Create Discussion"}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Community Sidebar */}
          <div className="space-y-8">
            {/* Member Stats */}
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="text-xl font-merriweather">Community Stats</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Active Members</span>
                    <span className="font-bold text-primary">12,847</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Countries</span>
                    <span className="font-bold text-healthcare-green">89</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Discussions</span>
                    <span className="font-bold text-secondary">{(discussions && Array.isArray(discussions) ? discussions.length : 0) || 2451}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Resources Shared</span>
                    <span className="font-bold text-accent">7,892</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Featured Members */}
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="text-xl font-merriweather">Featured Members</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center">
                    <div className="w-12 h-12 bg-primary rounded-full flex items-center justify-center text-white font-semibold mr-3">
                      E
                    </div>
                    <div>
                      <h4 className="font-semibold">Dr. Elena Vasquez</h4>
                      <p className="text-sm text-gray-500">Meducist Mentor</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <div className="w-12 h-12 bg-healthcare-green rounded-full flex items-center justify-center text-white font-semibold mr-3">
                      J
                    </div>
                    <div>
                      <h4 className="font-semibold">Prof. James Liu</h4>
                      <p className="text-sm text-gray-500">Ethics Specialist</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <div className="w-12 h-12 bg-secondary rounded-full flex items-center justify-center text-white font-semibold mr-3">
                      F
                    </div>
                    <div>
                      <h4 className="font-semibold">Dr. Fatima Al-Rashid</h4>
                      <p className="text-sm text-gray-500">Global Health Advocate</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Join Community CTA */}
            <Card className="shadow-lg bg-gradient-to-r from-primary to-secondary text-white">
              <CardContent className="p-6">
                <h3 className="text-xl font-merriweather font-bold mb-3">Join Our Community</h3>
                <p className="mb-4 opacity-90">
                  Connect with healthcare professionals worldwide who share the Meducist vision.
                </p>
                {!isAuthenticated && (
                  <Button 
                    onClick={() => window.location.href = '/api/login'}
                    className="w-full bg-white text-primary font-semibold hover:bg-white/90"
                  >
                    Become a Member
                  </Button>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
