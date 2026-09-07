"""
Base repository class providing common CRUD operations.

This module implements the repository pattern with support for
both synchronous and asynchronous database operations.
"""

from typing import TypeVar, Generic, Type, Optional, List, Any, Dict
from datetime import datetime

from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# For async support
try:
    from sqlalchemy.ext.asyncio import AsyncSession
    ASYNC_SUPPORT = True
except ImportError:
    ASYNC_SUPPORT = False
    AsyncSession = None

from ..models import Base

# Type variable for model classes
T = TypeVar("T", bound=Base)


class RepositoryError(Exception):
    """Base exception for repository errors."""
    pass


class NotFoundError(RepositoryError):
    """Resource not found."""
    pass


class DuplicateError(RepositoryError):
    """Duplicate resource error."""
    pass


class BaseRepository(Generic[T]):
    """
    Base repository providing common CRUD operations.

    Usage:
        class PolicyRepository(BaseRepository[Policy]):
            def __init__(self, db: Session):
                super().__init__(Policy, db)

            def find_by_name(self, name: str) -> Optional[Policy]:
                return self.db.query(self.model).filter(
                    self.model.name == name
                ).first()
    """

    def __init__(self, model: Type[T], db: Session):
        """
        Initialize repository with model class and database session.

        Args:
            model: SQLAlchemy model class
            db: Database session
        """
        self.model = model
        self.db = db

    def get(self, id: Any) -> Optional[T]:
        """
        Get a single record by primary key.

        Args:
            id: Primary key value

        Returns:
            Model instance or None if not found
        """
        return self.db.query(self.model).get(id)

    def get_or_raise(self, id: Any) -> T:
        """
        Get a single record by primary key, raising if not found.

        Args:
            id: Primary key value

        Returns:
            Model instance

        Raises:
            NotFoundError: If record not found
        """
        result = self.get(id)
        if result is None:
            raise NotFoundError(f"{self.model.__name__} with id {id} not found")
        return result

    def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None,
        order_desc: bool = False,
    ) -> List[T]:
        """
        Get all records with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum records to return
            order_by: Column name to order by
            order_desc: Whether to order descending

        Returns:
            List of model instances
        """
        query = self.db.query(self.model)

        if order_by and hasattr(self.model, order_by):
            col = getattr(self.model, order_by)
            query = query.order_by(col.desc() if order_desc else col)

        return query.offset(skip).limit(limit).all()

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count records matching optional filters.

        Args:
            filters: Dictionary of field=value filters

        Returns:
            Count of matching records
        """
        query = self.db.query(func.count(self.model.id))

        if filters:
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)

        return query.scalar() or 0

    def exists(self, id: Any) -> bool:
        """
        Check if a record exists by primary key.

        Args:
            id: Primary key value

        Returns:
            True if exists, False otherwise
        """
        return self.db.query(
            self.db.query(self.model).filter(self.model.id == id).exists()
        ).scalar()

    def create(self, obj: T) -> T:
        """
        Create a new record.

        Args:
            obj: Model instance to create

        Returns:
            Created model instance with ID populated

        Raises:
            DuplicateError: If unique constraint violated
        """
        try:
            self.db.add(obj)
            self.db.commit()
            self.db.refresh(obj)
            return obj
        except IntegrityError as e:
            self.db.rollback()
            if "UNIQUE constraint failed" in str(e) or "duplicate key" in str(e).lower():
                raise DuplicateError(f"Duplicate {self.model.__name__}: {e}")
            raise

    def create_many(self, objects: List[T]) -> List[T]:
        """
        Create multiple records in a single transaction.

        Args:
            objects: List of model instances to create

        Returns:
            List of created model instances

        Raises:
            DuplicateError: If unique constraint violated
        """
        try:
            self.db.add_all(objects)
            self.db.commit()
            for obj in objects:
                self.db.refresh(obj)
            return objects
        except IntegrityError as e:
            self.db.rollback()
            if "UNIQUE constraint failed" in str(e) or "duplicate key" in str(e).lower():
                raise DuplicateError(f"Duplicate {self.model.__name__}: {e}")
            raise

    def update(self, id: Any, data: Dict[str, Any]) -> Optional[T]:
        """
        Update a record by primary key.

        Args:
            id: Primary key value
            data: Dictionary of fields to update

        Returns:
            Updated model instance or None if not found
        """
        obj = self.get(id)
        if obj is None:
            return None

        for field, value in data.items():
            if hasattr(obj, field):
                setattr(obj, field, value)

        # Update timestamp if exists
        if hasattr(obj, "updated_at"):
            obj.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(obj)
        return obj

    def update_or_raise(self, id: Any, data: Dict[str, Any]) -> T:
        """
        Update a record, raising if not found.

        Args:
            id: Primary key value
            data: Dictionary of fields to update

        Returns:
            Updated model instance

        Raises:
            NotFoundError: If record not found
        """
        result = self.update(id, data)
        if result is None:
            raise NotFoundError(f"{self.model.__name__} with id {id} not found")
        return result

    def delete(self, id: Any) -> bool:
        """
        Delete a record by primary key.

        Args:
            id: Primary key value

        Returns:
            True if deleted, False if not found
        """
        obj = self.get(id)
        if obj is None:
            return False

        self.db.delete(obj)
        self.db.commit()
        return True

    def delete_or_raise(self, id: Any) -> None:
        """
        Delete a record, raising if not found.

        Args:
            id: Primary key value

        Raises:
            NotFoundError: If record not found
        """
        if not self.delete(id):
            raise NotFoundError(f"{self.model.__name__} with id {id} not found")

    def delete_many(self, ids: List[Any]) -> int:
        """
        Delete multiple records by primary keys.

        Args:
            ids: List of primary key values

        Returns:
            Number of records deleted
        """
        result = self.db.query(self.model).filter(self.model.id.in_(ids)).delete(
            synchronize_session=False
        )
        self.db.commit()
        return result

    def find_by(self, **kwargs) -> List[T]:
        """
        Find records matching field=value criteria.

        Args:
            **kwargs: Field=value pairs to filter by

        Returns:
            List of matching model instances
        """
        query = self.db.query(self.model)

        for field, value in kwargs.items():
            if hasattr(self.model, field):
                query = query.filter(getattr(self.model, field) == value)

        return query.all()

    def find_one_by(self, **kwargs) -> Optional[T]:
        """
        Find a single record matching field=value criteria.

        Args:
            **kwargs: Field=value pairs to filter by

        Returns:
            Model instance or None if not found
        """
        query = self.db.query(self.model)

        for field, value in kwargs.items():
            if hasattr(self.model, field):
                query = query.filter(getattr(self.model, field) == value)

        return query.first()

    def filter(
        self,
        filters: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None,
        order_desc: bool = False,
    ) -> List[T]:
        """
        Filter records with complex criteria.

        Supports operators in field names:
            - field__gt: greater than
            - field__gte: greater than or equal
            - field__lt: less than
            - field__lte: less than or equal
            - field__ne: not equal
            - field__in: in list
            - field__like: LIKE pattern
            - field__ilike: case-insensitive LIKE

        Args:
            filters: Dictionary of field=value or field__op=value
            skip: Number of records to skip
            limit: Maximum records to return
            order_by: Column name to order by
            order_desc: Whether to order descending

        Returns:
            List of matching model instances
        """
        query = self.db.query(self.model)

        for key, value in filters.items():
            if value is None:
                continue

            # Parse operator from key
            parts = key.split("__")
            field = parts[0]
            op = parts[1] if len(parts) > 1 else "eq"

            if not hasattr(self.model, field):
                continue

            col = getattr(self.model, field)

            if op == "eq":
                query = query.filter(col == value)
            elif op == "ne":
                query = query.filter(col != value)
            elif op == "gt":
                query = query.filter(col > value)
            elif op == "gte":
                query = query.filter(col >= value)
            elif op == "lt":
                query = query.filter(col < value)
            elif op == "lte":
                query = query.filter(col <= value)
            elif op == "in":
                query = query.filter(col.in_(value))
            elif op == "like":
                query = query.filter(col.like(value))
            elif op == "ilike":
                query = query.filter(col.ilike(value))

        if order_by and hasattr(self.model, order_by):
            col = getattr(self.model, order_by)
            query = query.order_by(col.desc() if order_desc else col)

        return query.offset(skip).limit(limit).all()

    def paginate(
        self,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        order_desc: bool = False,
    ) -> Dict[str, Any]:
        """
        Get paginated results with metadata.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            filters: Optional filters
            order_by: Column to order by
            order_desc: Descending order

        Returns:
            Dict with items, total, page, per_page, pages
        """
        skip = (page - 1) * per_page

        if filters:
            items = self.filter(
                filters, skip=skip, limit=per_page,
                order_by=order_by, order_desc=order_desc
            )
            total = len(self.filter(filters, skip=0, limit=1000000))
        else:
            items = self.get_all(
                skip=skip, limit=per_page,
                order_by=order_by, order_desc=order_desc
            )
            total = self.count()

        pages = (total + per_page - 1) // per_page if per_page > 0 else 0

        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }


class AsyncBaseRepository(Generic[T]):
    """
    Async version of BaseRepository for async database operations.

    Usage with FastAPI:
        async def get_items(db: AsyncSession = Depends(get_async_db)):
            repo = AsyncBaseRepository(Item, db)
            return await repo.get_all()
    """

    def __init__(self, model: Type[T], db: "AsyncSession"):
        self.model = model
        self.db = db

    async def get(self, id: Any) -> Optional[T]:
        """Get a single record by primary key."""
        result = await self.db.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def get_or_raise(self, id: Any) -> T:
        """Get a single record, raising if not found."""
        result = await self.get(id)
        if result is None:
            raise NotFoundError(f"{self.model.__name__} with id {id} not found")
        return result

    async def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None,
        order_desc: bool = False,
    ) -> List[T]:
        """Get all records with pagination."""
        query = select(self.model)

        if order_by and hasattr(self.model, order_by):
            col = getattr(self.model, order_by)
            query = query.order_by(col.desc() if order_desc else col)

        query = query.offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count records matching optional filters."""
        query = select(func.count()).select_from(self.model)

        if filters:
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.where(getattr(self.model, field) == value)

        result = await self.db.execute(query)
        return result.scalar() or 0

    async def create(self, obj: T) -> T:
        """Create a new record."""
        try:
            self.db.add(obj)
            await self.db.commit()
            await self.db.refresh(obj)
            return obj
        except IntegrityError as e:
            await self.db.rollback()
            if "UNIQUE constraint failed" in str(e) or "duplicate key" in str(e).lower():
                raise DuplicateError(f"Duplicate {self.model.__name__}: {e}")
            raise

    async def update(self, id: Any, data: Dict[str, Any]) -> Optional[T]:
        """Update a record by primary key."""
        obj = await self.get(id)
        if obj is None:
            return None

        for field, value in data.items():
            if hasattr(obj, field):
                setattr(obj, field, value)

        if hasattr(obj, "updated_at"):
            obj.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(obj)
        return obj

    async def delete(self, id: Any) -> bool:
        """Delete a record by primary key."""
        obj = await self.get(id)
        if obj is None:
            return False

        await self.db.delete(obj)
        await self.db.commit()
        return True

    async def find_by(self, **kwargs) -> List[T]:
        """Find records matching field=value criteria."""
        query = select(self.model)

        for field, value in kwargs.items():
            if hasattr(self.model, field):
                query = query.where(getattr(self.model, field) == value)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def find_one_by(self, **kwargs) -> Optional[T]:
        """Find a single record matching criteria."""
        query = select(self.model)

        for field, value in kwargs.items():
            if hasattr(self.model, field):
                query = query.where(getattr(self.model, field) == value)

        result = await self.db.execute(query.limit(1))
        return result.scalar_one_or_none()
