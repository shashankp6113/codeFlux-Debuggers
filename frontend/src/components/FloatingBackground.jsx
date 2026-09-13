import React, { useEffect, useState } from 'react';
import { Mail, Shield, Zap, Search } from 'lucide-react';

export default function FloatingBackground() {
  const [particles, setParticles] = useState([]);

  useEffect(() => {
    // Increased particle count for better page-wide coverage
    const newParticles = Array.from({ length: 30 }).map((_, i) => ({
      id: i,
      size: Math.random() * 40 + 20, 
      left: Math.random() * 100, 
      top: Math.random() * 100,
      duration: Math.random() * 15 + 15, 
      delay: Math.random() * -30, 
      blur: Math.random() * 4, 
      opacity: Math.random() * 0.15 + 0.05, 
      Icon: [Mail, Shield, Search, Zap][Math.floor(Math.random() * 4)],
      color: ['#1a73e8', '#10b981', '#8b5cf6', '#f59e0b'][Math.floor(Math.random() * 4)]
    }));
    setParticles(newParticles);
  }, []);

  return (
    <div className="floating-bg-container" aria-hidden="true" style={{ position: 'absolute', top: 0, left: 0, width: '100vw', height: '100vh', overflow: 'hidden', zIndex: 0, pointerEvents: 'none' }}>
      {/* Light trails / glowing orbs */}
      <div className="glow-orb orb-1"></div>
      <div className="glow-orb orb-2"></div>
      
      {particles.map((p) => {
        const { Icon } = p;
        return (
          <div
            key={p.id}
            className="floating-particle"
            style={{
              position: 'absolute',
              left: `${p.left}%`,
              top: `${p.top}%`,
              width: `${p.size}px`,
              height: `${p.size}px`,
              animationDuration: `${p.duration}s`,
              animationDelay: `${p.delay}s`,
              filter: `blur(${p.blur}px)`,
              opacity: p.opacity,
              color: p.color
            }}
          >
            <Icon size={p.size} strokeWidth={1.5} />
          </div>
        );
      })}
    </div>
  );
}
