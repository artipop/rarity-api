import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import EmailStr
from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Integer,
    LargeBinary,
    String,
    ForeignKey,
    DateTime,
    UniqueConstraint,
    func,
    UUID
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column

Base = declarative_base()


class ManufacturerCity(Base):
    __tablename__ = "manufacturer_cities"

    manufacturer_id: Mapped[int] = mapped_column(ForeignKey("manufacturers.id"), primary_key=True)
    city_id: Mapped[int] = mapped_column(ForeignKey("cities.id"), primary_key=True)

    manufacturer: Mapped["Manufacturer"] = relationship("Manufacturer", back_populates="cities")
    city: Mapped["City"] = relationship("City", back_populates="manufacturers")


class User(Base):
    __tablename__ = 'users'
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    email: Mapped[EmailStr] = mapped_column(String(255), unique=True, nullable=False)
    # all names are nullable at the creation and then set via put
    first_name: Mapped[String] = mapped_column(String(255), nullable=True)
    second_name: Mapped[String] = mapped_column(String(255), nullable=True)
    last_name: Mapped[String] = mapped_column(String(255), nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=True)  # TODO: should be false!!!
    verify_token: Mapped[Optional[str]]
    token_expires: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True))
    subscription = relationship("Subscription", back_populates="user")
    tokens = relationship("Token", back_populates="user")
    auth_credentials = relationship("AuthCredentials", back_populates="user")
    favourites: Mapped[List["UserFavourites"]] = relationship("UserFavourites", back_populates="user")


class AuthCredentials(Base):
    __tablename__ = 'auth_credentials'
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    auth_type: Mapped[str] = mapped_column(nullable=False)
    password_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, server_default=func.now())

    user = relationship("User", back_populates="auth_credentials")

    __table_args__ = (
        UniqueConstraint('auth_type', 'user_id', name='uq_auth_type_user'),
    )


class Country(Base):
    __tablename__ = 'countries'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    regions: Mapped[List["Region"]] = relationship("Region", back_populates="country")


class Manufacturer(Base):
    __tablename__ = 'manufacturers'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    cities: Mapped[List["ManufacturerCity"]] = relationship("ManufacturerCity", back_populates="manufacturer")
    items: Mapped["Item"] = relationship("Item", back_populates="manufacturer")


class UserFavourites(Base):
    __tablename__ = 'user_favourites'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id'), nullable=False)
    item_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id'), nullable=False)
    item: Mapped["Item"] = relationship("Item", back_populates="favourites")
    user: Mapped["User"] = relationship("User", back_populates="favourites")


class Item(Base):
    __tablename__ = 'items'
    id: Mapped[int] = mapped_column(primary_key=True)
    # book ID
    rp: Mapped[Optional[int]]
    name: Mapped[Optional[str]]
    description: Mapped[Optional[str]]
    production_years: Mapped[str]  # Можно хранить как JSON или просто строку с диапазонами
    photo_links: Mapped[Optional[str]]  # Можно хранить ссылки в формате JSON
    manufacturer_id: Mapped[int] = mapped_column(Integer, ForeignKey('manufacturers.id'), nullable=False)
    manufacturer: Mapped["Manufacturer"] = relationship("Manufacturer", back_populates="items")
    source: Mapped[Optional[str]]
    favourites: Mapped[List["UserFavourites"]] = relationship("UserFavourites", back_populates="item")


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

    region_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('regions.id'), nullable=True)
    region: Mapped["Region"] = relationship("Region", back_populates="cities")
    manufacturers: Mapped[List["ManufacturerCity"]] = relationship("ManufacturerCity", back_populates="city")


class SearchHistory(Base):
    __tablename__ = "search_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    region_name: Mapped[Optional[str]]
    country_name: Mapped[Optional[str]]
    manufacturer_name: Mapped[Optional[str]]
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), default=func.now())


class Subscription(Base):
    __tablename__ = 'subscriptions'

    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String(100))
    expiration_date: Mapped[datetime] = mapped_column(TIMESTAMP)
    provider: Mapped[str] = mapped_column(String(100), nullable=True)  # ?
    invoice_id: Mapped[Optional[str]] = mapped_column(String(100))  # TODO!
    invoice_date: Mapped[datetime] = mapped_column(TIMESTAMP)

    user_id: Mapped[UUID] = mapped_column(UUID, ForeignKey('users.id'))
    user = relationship('User', back_populates='subscription')


class Symbol(Base):
    __tablename__ = "symbols"
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[Optional[str]]

    rps: Mapped[List["SymbolRp"]] = relationship("SymbolRp", back_populates="symbol")
    locales: Mapped[List["SymbolsLocale"]] = relationship("SymbolsLocale", back_populates="symbol")


class SymbolRp(Base):
    __tablename__ = "symbols_rp"
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    symbol_id: Mapped[UUID] = mapped_column(UUID, ForeignKey("symbols.id", ondelete="SET NULL"))
    rp: Mapped[int]

    symbol: Mapped["Symbol"] = relationship("Symbol", back_populates="rps")


class SymbolsLocale(Base):
    __tablename__ = "symbols_locale"
    id: Mapped[UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    symbol_id: Mapped[UUID] = mapped_column(UUID, ForeignKey("symbols.id", ondelete="SET NULL"))
    translit: Mapped[Optional[str]]
    locale_de: Mapped[Optional[str]]
    locale_ru: Mapped[Optional[str]]
    locale_en: Mapped[Optional[str]]

    symbol: Mapped["Symbol"] = relationship("Symbol", back_populates="locales")
