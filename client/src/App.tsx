import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/Landing";
import Home from "@/pages/Home";
import About from "@/pages/About";
import CoreValues from "@/pages/CoreValues";
import Resources from "@/pages/Resources";
import Community from "@/pages/Community";
import Events from "@/pages/Events";
import Blog from "@/pages/Blog";
import Navigation from "@/components/Navigation";
import Footer from "@/components/Footer";

function Router() {
  const { isAuthenticated, isLoading } = useAuth();

  return (
    <div className="min-h-screen flex flex-col">
      <Navigation />
      <main className="flex-1">
        <Switch>
          {isLoading || !isAuthenticated ? (
            <>
              <Route path="/" component={Landing} />
              <Route path="/about" component={About} />
              <Route path="/core-values" component={CoreValues} />
              <Route path="/resources" component={Resources} />
              <Route path="/community" component={Community} />
              <Route path="/events" component={Events} />
              <Route path="/blog" component={Blog} />
            </>
          ) : (
            <>
              <Route path="/" component={Home} />
              <Route path="/about" component={About} />
              <Route path="/core-values" component={CoreValues} />
              <Route path="/resources" component={Resources} />
              <Route path="/community" component={Community} />
              <Route path="/events" component={Events} />
              <Route path="/blog" component={Blog} />
            </>
          )}
          <Route component={NotFound} />
        </Switch>
      </main>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
