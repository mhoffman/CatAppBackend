# global imports
import os
import json
import sqlalchemy
import sqlalchemy.types
import sqlalchemy.ext.declarative
from sqlalchemy import or_, func, and_, desc
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, ARRAY, INET
from sqlalchemy.dialects import postgresql
from sqlalchemy import Integer, String, Column, Float, Index, Date, Boolean

SCHEMA = os.environ.get('DB_SCHEMA_FIREWORKS', 'public')


if os.environ.get('DB_PASSWORD_FIREWORKS', ''):
    url = sqlalchemy.engine.url.URL('postgres',
                                    username=os.environ.get(
                                        'DB_USER_FIREWORKS', 'fireworks'),
                                    host=os.environ.get(
                                        'DB_HOST_FIREWORKS',
                                        'catalysishub.c8gwuc8jwb7l.us-west-2.rds.amazonaws.com'),
                                    database=os.environ.get(
                                        'DB_DATABASE_FIREWORKS', 'catalysishub'),
                                    password=os.environ.get(
                                        'DB_PASSWORD_FIREWORKS', ''),
                                    # port=5432,
                                    )
else:
    url = sqlalchemy.engine.url.URL('postgres',
                                    username='postgres',
                                    host='localhost',
                                    #port=5432,
                                    database='travis_ci_test_fireworks')
    url = sqlalchemy.engine.url.URL('sqlite:///user_database.db')

print(url)
engine = sqlalchemy.create_engine(
    'sqlite:///upload_database.db',
    echo=True,
    convert_unicode=True,
)

session = sqlalchemy.orm.scoped_session(sqlalchemy.orm.sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
))

#inspector = sqlalchemy.engine.reflection.Inspector.from_engine(
        #engine
        #)

Base = sqlalchemy.ext.declarative.declarative_base()
Base.query = session.query_property()
metadata = Base.metadata

class User(Base):
    __tablename__ = 'user'
    #__table_args__ = ({'schema': SCHEMA},)

    username = Column(String, primary_key=True, index=True)
    token = Column(String,)
    signup_date = Column(Date, index=True)
    login_date = Column(Date, index=True)
    email = Column(String)
    email_ok = Column(Boolean,)
    signup_ip = Column(String)
    login_ip = Column(String)


    def __repr__(self):
        return f'{self.username}, email: {self.email} IP {self.login_ip}'


