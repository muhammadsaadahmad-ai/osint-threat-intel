from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import DATABASE_URL

Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True)
    value = Column(String(500), nullable=False)
    ioc_type = Column(String(50))
    source = Column(String(100))
    mitre_tag = Column(String(200))
    raw_context = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    severity = Column(String(20), default="medium")

class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(Integer, primary_key=True)
    name = Column(String(200))
    iocs = Column(Text)
    ttps = Column(Text)
    source = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text)

def init_db():
    Base.metadata.create_all(engine)
    print("[+] Database initialized.")
