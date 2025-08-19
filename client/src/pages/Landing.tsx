import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import ValueCard from "@/components/ValueCard";

export default function Landing() {
  return (
    <div className="pt-16">
      {/* Hero Section with Premium Gradient */}
      <section className="relative gradient-premium text-white overflow-hidden">
        <div className="absolute inset-0 bg-black opacity-10"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-32">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div className="animate-fade-in-left">
              <h1 className="text-5xl md:text-7xl font-merriweather font-bold mb-6 leading-tight">
                <span className="text-gradient-gold">Meducism:</span> A New Ethos for Humanity
              </h1>
              <p className="text-xl md:text-2xl mb-10 leading-relaxed opacity-95">
                A moral philosophy and practical framework that treats healthcare knowledge, ethical conduct, and self-care as universal human duties—not just professional obligations.
              </p>
              <div className="flex flex-col sm:flex-row gap-4">
                <Link href="/about">
                  <Button className="btn-premium text-white px-10 py-4 rounded-xl font-semibold text-lg shadow-premium hover-lift">
                    Explore Philosophy
                  </Button>
                </Link>
                <Button 
                  onClick={() => window.location.href = '/api/login'}
                  className="glass border-2 border-white/30 text-white hover:bg-white/20 px-10 py-4 rounded-xl font-semibold text-lg backdrop-blur-md hover-lift"
                >
                  Join Community
                </Button>
              </div>
            </div>
            <div className="relative animate-fade-in-right">
              <div className="absolute inset-0 gradient-gold opacity-20 rounded-2xl"></div>
              <img 
                src="https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=800&h=600" 
                alt="Healthcare professionals collaborating" 
                className="rounded-2xl shadow-premium w-full h-auto relative z-10"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Philosophy Overview with Elegant Cards */}
      <section className="py-24 bg-gradient-to-b from-white to-light-grey">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 animate-fade-in-up">
            <h2 className="text-4xl md:text-5xl font-merriweather font-bold text-gradient-primary mb-8">
              The Philosophy of Meducism
            </h2>
            <p className="text-xl md:text-2xl text-text-secondary max-w-3xl mx-auto leading-relaxed">
              Meducism's central claim: The ultimate goal of humanity—happiness through well-being—can only be achieved if everyone possesses the mindset, skills, and ethical grounding of a healthcare professional.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
            <Card className="shadow-premium hover-lift animate-fade-in-up animate-delay-100 border-0">
              <CardContent className="p-10">
                <div className="w-20 h-20 gradient-primary rounded-2xl flex items-center justify-center mb-8 mx-auto shadow-lg">
                  <i className="fas fa-heart text-white text-3xl"></i>
                </div>
                <h3 className="text-2xl font-merriweather font-bold text-center mb-5 text-text-primary">Universal Responsibility</h3>
                <p className="text-lg text-text-secondary text-center leading-relaxed">
                  Everyone's well-being is interconnected. Mutual responsibility forms the foundation of a compassionate society.
                </p>
              </CardContent>
            </Card>
            
            <Card className="shadow-premium hover-lift animate-fade-in-up animate-delay-200 border-0">
              <CardContent className="p-10">
                <div className="w-20 h-20 gradient-secondary rounded-2xl flex items-center justify-center mb-8 mx-auto shadow-lg">
                  <i className="fas fa-book-open text-white text-3xl"></i>
                </div>
                <h3 className="text-2xl font-merriweather font-bold text-center mb-5 text-text-primary">Knowledge Sharing</h3>
                <p className="text-lg text-text-secondary text-center leading-relaxed">
                  Passing medical literacy to future generations is a moral obligation that ensures sustainable well-being.
                </p>
              </CardContent>
            </Card>
            
            <Card className="shadow-premium hover-lift animate-fade-in-up animate-delay-300 border-0">
              <CardContent className="p-10">
                <div className="w-20 h-20 gradient-gold rounded-2xl flex items-center justify-center mb-8 mx-auto shadow-lg">
                  <i className="fas fa-balance-scale text-white text-3xl"></i>
                </div>
                <h3 className="text-2xl font-merriweather font-bold text-center mb-5 text-text-primary">Ethical Foundation</h3>
                <p className="text-lg text-text-secondary text-center leading-relaxed">
                  Core principles are universal yet adaptable to cultural and situational contexts, ensuring flexibility with integrity.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Core Values Preview */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-merriweather font-bold text-text-primary mb-6">
              Four Core Values of Meducism
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Each core aspect represents a fundamental area of development, encompassing dedication to health proficiency, knowledge-sharing, ethical commitment, and personal well-being.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
            <ValueCard
              title="Healthcare Proficiency"
              description="Mastery of medical knowledge and clinical skills as a commitment to the art and science of medicine."
              icon="stethoscope"
              color="primary"
              features={[
                "Medical Knowledge Mastery",
                "Clinical Skill Proficiency",
                "Continuous Learning"
              ]}
            />

            <ValueCard
              title="Medical Education"
              description="Sharing knowledge is as important as practicing it. Every Meducist has a duty to cultivate future generations."
              icon="chalkboard-teacher"
              color="healthcare-green"
              features={[
                "Educational Passion",
                "Mentorship Engagement",
                "Learning Resources"
              ]}
            />

            <ValueCard
              title="Ethical Self-Respect"
              description="True ethical conduct means acting in ways that support the well-being of self, patient, and humanity."
              icon="shield-alt"
              color="secondary"
              features={[
                "Ethical Integrity",
                "Ethical Leadership",
                "Rational Decision-Making"
              ]}
            />

            <ValueCard
              title="Self-Care"
              description="Effective caregiving must start with self-care. Personal well-being ensures sustainable compassion for others."
              icon="leaf"
              color="accent"
              features={[
                "Physical Well-Being",
                "Mental Resilience",
                "Boundaries & Balance"
              ]}
            />
          </div>

          <div className="text-center">
            <Link href="/core-values">
              <Button className="bg-primary text-white px-8 py-3 rounded-lg hover:bg-primary/90">
                Explore All Values
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
