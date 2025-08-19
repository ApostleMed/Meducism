import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Event } from "@shared/schema";

interface EventCardProps {
  event: Event;
}

export default function EventCard({ event }: EventCardProps) {
  const startDate = new Date(event.startDate);
  const endDate = new Date(event.endDate);
  
  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      year: 'numeric' 
    });
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { 
      hour: 'numeric',
      minute: '2-digit',
      hour12: true 
    });
  };

  return (
    <Card className="shadow-lg hover:shadow-xl transition-shadow">
      <CardContent className="p-6">
        <div className="flex items-start space-x-4">
          <div className="bg-primary text-white rounded-lg p-3 text-center min-w-[80px]">
            <div className="text-xs font-semibold">
              {startDate.toLocaleDateString('en-US', { month: 'short' }).toUpperCase()}
            </div>
            <div className="text-2xl font-bold">
              {startDate.getDate()}
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-xl font-merriweather font-bold mb-2">{event.title}</h3>
            <p className="text-gray-600 mb-3">
              {event.description}
            </p>
            <div className="flex flex-col sm:flex-row sm:items-center text-sm text-gray-500 space-y-1 sm:space-y-0 sm:space-x-4 mb-3">
              <span>
                <i className={`fas ${event.isOnline ? 'fa-globe' : 'fa-map-marker-alt'} mr-1`}></i>
                {event.location}
              </span>
              <span>
                <i className="fas fa-clock mr-1"></i>
                {formatTime(startDate)} - {formatTime(endDate)}
              </span>
              {!event.isOnline && (
                <span>
                  <i className="fas fa-calendar mr-1"></i>
                  {formatDate(startDate)}
                  {startDate.toDateString() !== endDate.toDateString() && ` - ${formatDate(endDate)}`}
                </span>
              )}
            </div>
            {event.registrationUrl && (
              <Button className="text-primary hover:text-secondary font-semibold p-0 h-auto bg-transparent hover:bg-transparent">
                Register Now <i className="fas fa-arrow-right ml-1"></i>
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
