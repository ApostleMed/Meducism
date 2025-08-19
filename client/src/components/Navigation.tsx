import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

export default function Navigation() {
  const [location] = useLocation();
  const { isAuthenticated } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const navItems = [
    { href: "/about", label: "About" },
    { href: "/core-values", label: "Core Values" },
    { href: "/resources", label: "Resources" },
    { href: "/community", label: "Community" },
    { href: "/events", label: "Events" },
    { href: "/blog", label: "Blog" },
  ];

  return (
    <nav className="glass shadow-premium fixed w-full top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center">
            <Link href="/" className="flex-shrink-0 flex items-center space-x-3 hover-lift">
              <img 
                src="/attached_assets/getimg_ai_img-mr9LLIdUu2DLhhqv1ZYTV_1754813070871.jpeg" 
                alt="Meducism Logo" 
                className="h-10 w-auto"
              />
              <h1 className="text-2xl font-merriweather font-bold text-gradient-primary">Meducism</h1>
            </Link>
          </div>
          
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-4">
              {navItems.map((item) => (
                <Link key={item.href} href={item.href}>
                  <span className={`px-3 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer ${
                    location === item.href
                      ? "text-primary bg-blue-50"
                      : "text-text-primary hover:text-primary"
                  }`}>
                    {item.label}
                  </span>
                </Link>
              ))}
            </div>
          </div>
          
          <div className="hidden md:block">
            <div className="ml-4 flex items-center md:ml-6 space-x-3">
              {isAuthenticated ? (
                <Button 
                  onClick={() => window.location.href = '/api/logout'}
                  variant="outline"
                  className="border-primary text-primary hover:bg-primary hover:text-white"
                >
                  Logout
                </Button>
              ) : (
                <>
                  <Button
                    onClick={() => window.location.href = '/api/login'}
                    className="btn-premium text-white shadow-lg hover-lift"
                  >
                    Join Movement
                  </Button>
                  <Button
                    onClick={() => window.location.href = '/api/login'}
                    variant="outline"
                    className="glass border-2 border-primary/30 text-primary hover:bg-primary/10"
                  >
                    Login
                  </Button>
                </>
              )}
            </div>
          </div>
          
          <div className="md:hidden">
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="text-text-primary hover:text-primary"
            >
              <i className={`fas ${isMobileMenuOpen ? 'fa-times' : 'fa-bars'} text-xl`}></i>
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden">
            <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-white border-t">
              {navItems.map((item) => (
                <Link key={item.href} href={item.href}>
                  <span
                    className={`block px-3 py-2 rounded-md text-base font-medium transition-colors cursor-pointer ${
                      location === item.href
                        ? "text-primary bg-blue-50"
                        : "text-text-primary hover:text-primary"
                    }`}
                    onClick={() => setIsMobileMenuOpen(false)}
                  >
                    {item.label}
                  </span>
                </Link>
              ))}
              <div className="pt-4 pb-3 border-t border-gray-200">
                {isAuthenticated ? (
                  <Button 
                    onClick={() => {
                      window.location.href = '/api/logout';
                      setIsMobileMenuOpen(false);
                    }}
                    variant="outline"
                    className="w-full border-primary text-primary hover:bg-primary hover:text-white"
                  >
                    Logout
                  </Button>
                ) : (
                  <div className="space-y-2">
                    <Button
                      onClick={() => {
                        window.location.href = '/api/login';
                        setIsMobileMenuOpen(false);
                      }}
                      className="w-full bg-primary text-white hover:bg-primary/90"
                    >
                      Join Movement
                    </Button>
                    <Button
                      onClick={() => {
                        window.location.href = '/api/login';
                        setIsMobileMenuOpen(false);
                      }}
                      variant="outline"
                      className="w-full border-primary text-primary hover:bg-primary hover:text-white"
                    >
                      Login
                    </Button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
}
