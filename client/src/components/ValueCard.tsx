import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ValueCardProps {
  title: string;
  description: string;
  icon: string;
  color: "primary" | "healthcare-green" | "secondary" | "accent";
  features: string[];
  detailed?: boolean;
}

const colorClasses = {
  primary: "from-primary to-blue-600 text-primary",
  "healthcare-green": "from-healthcare-green to-green-600 text-healthcare-green",
  secondary: "from-secondary to-pink-600 text-secondary",
  accent: "from-accent to-yellow-600 text-accent",
};

export default function ValueCard({ title, description, icon, color, features, detailed = false }: ValueCardProps) {
  return (
    <Card className={`bg-gradient-to-br ${colorClasses[color].split(' ')[0]} ${colorClasses[color].split(' ')[1]} text-white hover:shadow-2xl transition-all duration-300 transform hover:-translate-y-2`}>
      <CardContent className="p-8">
        <div className="flex items-center mb-6">
          <div className="w-16 h-16 bg-white bg-opacity-20 rounded-full flex items-center justify-center mr-4">
            <i className={`fas fa-${icon} text-2xl`}></i>
          </div>
          <h3 className="text-2xl font-merriweather font-bold">{title}</h3>
        </div>
        <p className={`mb-6 opacity-90 ${detailed ? 'text-base' : ''}`}>
          {description}
        </p>
        <div className="space-y-3">
          {features.map((feature, index) => (
            <div key={index} className="flex items-center">
              <i className="fas fa-check-circle mr-3"></i>
              <span>{feature}</span>
            </div>
          ))}
        </div>
        {!detailed && (
          <Button className={`mt-6 bg-white ${colorClasses[color].split(' ')[2]} px-6 py-2 rounded-lg font-semibold hover:bg-opacity-90 transition-colors`}>
            Learn More
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
