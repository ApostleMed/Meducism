import { Card, CardContent } from "@/components/ui/card";

export default function About() {
  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            About Meducism
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            A comprehensive moral philosophy that reimagines healthcare as a universal human responsibility
          </p>
        </div>
      </section>

      {/* Philosophy Content */}
      <section className="py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="prose prose-lg max-w-none">
            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">
              The Vision
            </h2>
            <p className="text-gray-600 mb-8 text-lg leading-relaxed">
              Meducism represents a paradigm shift in how we think about healthcare, education, and human responsibility. At its core, Meducism posits that the ultimate goal of humanity—achieving happiness through comprehensive well-being—can only be realized when every individual embodies the mindset, skills, and ethical framework traditionally associated with healthcare professionals.
            </p>

            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">
              Core Philosophy
            </h2>
            <p className="text-gray-600 mb-8 text-lg leading-relaxed">
              Unlike traditional approaches that compartmentalize healthcare as a professional domain, Meducism advocates for universal healthcare literacy and responsibility. This philosophy recognizes that health and well-being are not merely personal concerns but collective imperatives that require active participation from all members of society.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 my-12">
              <Card className="shadow-lg">
                <CardContent className="p-8">
                  <div className="w-16 h-16 bg-primary rounded-full flex items-center justify-center mb-6">
                    <i className="fas fa-globe text-white text-2xl"></i>
                  </div>
                  <h3 className="text-xl font-merriweather font-bold mb-4">Global Impact</h3>
                  <p className="text-gray-600">
                    Meducism envisions a world where healthcare knowledge transcends professional boundaries, creating communities of informed, caring individuals.
                  </p>
                </CardContent>
              </Card>

              <Card className="shadow-lg">
                <CardContent className="p-8">
                  <div className="w-16 h-16 bg-healthcare-green rounded-full flex items-center justify-center mb-6">
                    <i className="fas fa-lightbulb text-white text-2xl"></i>
                  </div>
                  <h3 className="text-xl font-merriweather font-bold mb-4">Innovation</h3>
                  <p className="text-gray-600">
                    By democratizing healthcare knowledge, Meducism fosters innovation and creative solutions to global health challenges.
                  </p>
                </CardContent>
              </Card>
            </div>

            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">
              Historical Context
            </h2>
            <p className="text-gray-600 mb-8 text-lg leading-relaxed">
              The development of Meducism arose from observations of healthcare disparities, the limitations of traditional medical education, and the recognition that many health challenges require community-based solutions. Drawing inspiration from ancient philosophical traditions that emphasized virtue ethics and social responsibility, Meducism adapts these timeless principles for contemporary healthcare challenges.
            </p>

            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">
              The Four Pillars
            </h2>
            <p className="text-gray-600 mb-8 text-lg leading-relaxed">
              Meducism is built upon four fundamental pillars that together create a comprehensive framework for healthcare excellence and human flourishing. These pillars—Healthcare Proficiency, Medical Education Capability, Ethical Self-Respect, and Self-Care—work synergistically to develop individuals who can contribute meaningfully to the health and well-being of their communities.
            </p>

            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8">
              Implementation and Practice
            </h2>
            <p className="text-gray-600 mb-8 text-lg leading-relaxed">
              Meducism is not merely a theoretical framework but a practical approach to living and working. It provides concrete guidelines for personal development, professional practice, and community engagement. Whether applied in clinical settings, educational institutions, or community organizations, Meducism offers tools and principles that enhance both individual capabilities and collective outcomes.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
