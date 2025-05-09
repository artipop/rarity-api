from datetime import datetime

from typing import List, Optional
import uuid
from pydantic import EmailStr
from sqlalchemy import (
    TIMESTAMP, 
    Boolean, 
    Column, 
    Integer, 
    LargeBinary, 
    String, 
    ForeignKey, 
    Table, 
    DateTime, 
    UniqueConstraint, 
    func,
    UUID
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column

from rarity_api.core.database.repos.abstract_repo import AbstractRepository

Base = declarative_base()

# Определяем таблицу для связи многие-ко-многим между Производителем и Городом
manufacturer_city_association = Table(
    'manufacturer_city', Base.metadata,
    Column('manufacturer_id', Integer, ForeignKey('manufacturers.id'), primary_key=True),
    Column('city_id', Integer, ForeignKey('cities.id'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    email: Mapped[EmailStr] = mapped_column(String(255), unique=True, nullable=False)
    # all names are nullable at the creation and then set via put
    first_name: Mapped[String] = mapped_column(String(255), nullable=True)
    second_name: Mapped[String] = mapped_column(String(255), nullable=True)
    last_name: Mapped[String] = mapped_column(String(255), nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    subscription = relationship("Subscription", back_populates="user")
    tokens = relationship("Token", back_populates="user")
    auth_credentials = relationship("AuthCredentials", back_populates="user")


class Country(Base):
    __tablename__ = 'countries'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    regions: Mapped[List["Region"]] = relationship("Region", back_populates="country")

class AuthCredentials(Base):
    __tablename__ = 'auth_credentials'
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id'), nullable=False)
    auth_type: Mapped[str] = mapped_column(nullable=False)
    password_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())

    user = relationship("User", back_populates="auth_credentials")

    __table_args__ = (
        UniqueConstraint('auth_type', 'user_id', name='uq_auth_type_user'),
    )

class Token(Base):
    __tablename__ = 'tokens'
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id'), nullable=False)
    token: Mapped[str] = mapped_column(String(1024), nullable=False)
    token_type: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())

    user = relationship("User", back_populates="tokens")


class Region(Base):
    __tablename__ = 'regions'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    country_id: Mapped[int] = mapped_column(Integer, ForeignKey('countries.id'), nullable=False)
    country: Mapped["Country"] = relationship("Country", back_populates="regions")
    cities: Mapped["City"] = relationship("City", back_populates="region")


class City(Base):
    __tablename__ = 'cities'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]

    region_id: Mapped[int] = mapped_column(Integer, ForeignKey('regions.id'), nullable=False)
    region: Mapped["Region"] = relationship("Region", back_populates="cities")
    manufacturers: Mapped[List["Manufacturer"]] = relationship("Manufacturer", secondary=manufacturer_city_association, back_populates="cities")


class Manufacturer(Base):
    __tablename__ = 'manufacturers'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    cities: Mapped["City"] = relationship("City", secondary=manufacturer_city_association, back_populates="manufacturers")
    items: Mapped["Item"] = relationship("Item", back_populates="manufacturer")


class Item(Base):
    __tablename__ = 'items'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    description: Mapped[str]
    production_years: Mapped[str]  # Можно хранить как JSON или просто строку с диапазонами
    photo_links: Mapped[str]  # Можно хранить ссылки в формате JSON
    manufacturer_id: Mapped[int] = mapped_column(Integer, ForeignKey('manufacturers.id'), nullable=False)
    manufacturer: Mapped["Manufacturer"] = relationship("Manufacturer", back_populates="items")


class SearchHistory(Base):
    __tablename__ = "search_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    region_name: Mapped[str]
    country_name: Mapped[Optional[str]]
    manufacturer_name: Mapped[Optional[str]]
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), default=func.now())

class Subscription(Base):
    __tablename__ = 'subscriptions'

    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String(100))
    expiration_date: Mapped[datetime] = mapped_column(TIMESTAMP)
    provider: Mapped[str] = mapped_column(String(100), nullable=True)  # ?
    invoice_id: Mapped[str] = mapped_column(String(100))  # TODO!
    invoice_date: Mapped[datetime] = mapped_column(TIMESTAMP)

    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id'))
    user = relationship('User', back_populates='subscription')