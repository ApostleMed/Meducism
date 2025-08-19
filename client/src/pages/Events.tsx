import { useQuery } from "@tanstack/react-query";
import EventCard from "@/components/EventCard";

export default function Events() {
  const { data: events, isLoading } = useQuery({
    queryKey: ["/api/events"],
  });

  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            Events & Conferences
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            Join us for workshops, conferences, and community meetups focused on advancing Meducist principles worldwide.
          </p>
        </div>
      </section>

      {/* Events Content */}
      <section className="py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-12">
            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">Upcoming Events</h2>
            
            {isLoading ? (
              <div className="space-y-6">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="bg-white rounded-xl p-6 shadow-lg animate-pulse">
                    <div className="flex items-start space-x-4">
                      <div className="bg-gray-200 rounded-lg p-3 w-20 h-20"></div>
                      <div className="flex-1 space-y-2">
                        <div className="h-6 bg-gray-200 rounded w-3/4"></div>
                        <div className="h-4 bg-gray-200 rounded w-full"></div>
                        <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (events && Array.isArray(events) && events.length === 0) ? (
              <div className="text-center py-12">
                <div className="w-24 h-24 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-6">
                  <i className="fas fa-calendar text-gray-400 text-3xl"></i>
                </div>
                <h3 className="text-2xl font-merriweather font-bold text-gray-500 mb-4">
                  No upcoming events
                </h3>
                <p className="text-gray-400">
                  Check back soon for upcoming conferences and community events.
                </p>
              </div>
            ) : (
              <div className="space-y-6">
                {events && Array.isArray(events) && events.map((event: any) => (
                  <EventCard key={event.id} event={event} />
                ))}
              </div>
            )}

            {/* Default Events for Demo */}
            {!events && !isLoading && (
              <div className="space-y-6">
                <EventCard
                  event={{
                    id: "1",
                    title: "International Meducism Conference 2024",
                    description: "Join healthcare professionals worldwide for three days of discussions on implementing Meducist principles in modern healthcare.",
                    location: "Geneva, Switzerland",
                    isOnline: false,
                    startDate: new Date('2024-03-15T09:00:00'),
                    endDate: new Date('2024-03-17T18:00:00'),
                    registrationUrl: "#",
                    imageUrl: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                    createdAt: new Date()
                  }}
                />
                <EventCard
                  event={{
                    id: "2",
                    title: "Virtual Workshop: Ethical Leadership in Healthcare",
                    description: "Interactive online workshop focusing on developing ethical leadership skills through Meducist principles.",
                    location: "Online Event",
                    isOnline: true,
                    startDate: new Date('2024-04-22T14:00:00'),
                    endDate: new Date('2024-04-22T17:00:00'),
                    registrationUrl: "#",
                    imageUrl: "https://images.unsplash.com/photo-1582750433449-648ed127bb54?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                    createdAt: new Date()
                  }}
                />
                <EventCard
                  event={{
                    id: "3",
                    title: "Regional Meducist Meetup - North America",
                    description: "Connect with local practitioners and discuss implementing Meducism in diverse healthcare settings.",
                    location: "Toronto, Canada",
                    isOnline: false,
                    startDate: new Date('2024-05-08T10:00:00'),
                    endDate: new Date('2024-05-08T16:00:00'),
                    registrationUrl: "#",
                    imageUrl: "https://images.unsplash.com/photo-1559757175-0eb30cd8c063?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=200",
                    createdAt: new Date()
                  }}
                />
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
