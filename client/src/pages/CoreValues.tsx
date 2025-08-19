import ValueCard from "@/components/ValueCard";

export default function CoreValues() {
  return (
    <div className="pt-16">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary to-secondary text-white py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-merriweather font-bold mb-6">
            Four Core Values of Meducism
          </h1>
          <p className="text-xl leading-relaxed opacity-90">
            Each core aspect represents a fundamental area of development, encompassing dedication to health proficiency, knowledge-sharing, ethical commitment, and personal well-being.
          </p>
        </div>
      </section>

      {/* Core Values Content */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-16">
            <ValueCard
              title="Healthcare Proficiency"
              description="Mastery of medical knowledge and clinical skills as a commitment to the art and science of medicine. This pillar emphasizes the importance of continuous learning, evidence-based practice, and technical excellence in all healthcare-related activities."
              icon="stethoscope"
              color="primary"
              features={[
                "Medical Knowledge Mastery",
                "Clinical Skill Proficiency",
                "Continuous Learning",
                "Evidence-Based Practice",
                "Technical Excellence",
                "Professional Competency"
              ]}
              detailed={true}
            />

            <ValueCard
              title="Medical Education Capability"
              description="Sharing knowledge is as important as practicing it. Every Meducist has a duty to cultivate future generations through effective teaching, mentoring, and knowledge dissemination."
              icon="chalkboard-teacher"
              color="healthcare-green"
              features={[
                "Educational Passion",
                "Mentorship Engagement",
                "Learning Resources Development",
                "Curriculum Innovation",
                "Student Assessment",
                "Knowledge Transfer"
              ]}
              detailed={true}
            />

            <ValueCard
              title="Ethical Self-Respect"
              description="True ethical conduct means acting in ways that support the well-being of self, patient, and humanity. This involves maintaining moral integrity while adapting to diverse cultural contexts."
              icon="shield-alt"
              color="secondary"
              features={[
                "Ethical Integrity",
                "Ethical Leadership",
                "Rational Decision-Making",
                "Cultural Sensitivity",
                "Moral Courage",
                "Professional Boundaries"
              ]}
              detailed={true}
            />

            <ValueCard
              title="Self-Care"
              description="Effective caregiving must start with self-care. Personal well-being ensures sustainable compassion for others and prevents burnout in healthcare practice."
              icon="leaf"
              color="accent"
              features={[
                "Physical Well-Being",
                "Mental Resilience",
                "Boundaries & Balance",
                "Stress Management",
                "Personal Growth",
                "Sustainable Practice"
              ]}
              detailed={true}
            />
          </div>

          {/* Integration Section */}
          <div className="bg-light-grey rounded-xl p-8 md:p-12">
            <h2 className="text-3xl font-merriweather font-bold text-text-primary mb-8 text-center">
              Integration and Synergy
            </h2>
            <p className="text-lg text-gray-600 mb-8 text-center max-w-3xl mx-auto">
              The four core values of Meducism are not independent pillars but interconnected aspects that strengthen and reinforce each other. True Meducist practice requires the integration of all four values.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="text-center">
                <div className="w-20 h-20 bg-primary rounded-full flex items-center justify-center mb-6 mx-auto">
                  <i className="fas fa-puzzle-piece text-white text-3xl"></i>
                </div>
                <h3 className="text-xl font-merriweather font-bold mb-4">Interconnected Practice</h3>
                <p className="text-gray-600">
                  Each value supports and enhances the others, creating a comprehensive approach to healthcare excellence that addresses technical, educational, ethical, and personal dimensions.
                </p>
              </div>
              
              <div className="text-center">
                <div className="w-20 h-20 bg-healthcare-green rounded-full flex items-center justify-center mb-6 mx-auto">
                  <i className="fas fa-sync-alt text-white text-3xl"></i>
                </div>
                <h3 className="text-xl font-merriweather font-bold mb-4">Continuous Development</h3>
                <p className="text-gray-600">
                  Meducist practice involves ongoing development in all four areas, with regular self-assessment and commitment to growth in technical skills, teaching ability, ethical reasoning, and personal well-being.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
