import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link } from "wouter";

export default function Home() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="pt-16 min-h-screen bg-light-grey">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/3 mb-4"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="pt-16 min-h-screen bg-light-grey">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-12">
          <h1 className="text-4xl font-merriweather font-bold text-text-primary mb-4">
            Welcome back, {user && typeof user === 'object' && 'firstName' in user && user.firstName ? user.firstName : 'Meducist'}!
          </h1>
          <p className="text-xl text-gray-600">
            Continue your journey in the Meducism community
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {/* Quick Actions */}
          <Card className="shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center">
                <i className="fas fa-comments text-primary mr-3"></i>
                Community Discussions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Join conversations with fellow Meducists worldwide
              </p>
              <Link href="/community">
                <Button className="w-full bg-primary text-white">
                  Join Discussions
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center">
                <i className="fas fa-download text-healthcare-green mr-3"></i>
                Academic Resources
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Access comprehensive Meducism resources and guides
              </p>
              <Link href="/resources">
                <Button className="w-full bg-healthcare-green text-white">
                  Browse Resources
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center">
                <i className="fas fa-calendar text-secondary mr-3"></i>
                Upcoming Events
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Don't miss conferences and community meetups
              </p>
              <Link href="/events">
                <Button className="w-full bg-secondary text-white">
                  View Events
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>

        {/* User Actions */}
        <div className="mt-12 flex justify-center">
          <Button 
            onClick={() => window.location.href = '/api/logout'}
            variant="outline"
            className="px-8 py-3"
          >
            Logout
          </Button>
        </div>
      </div>
    </div>
  );
}
