#!/usr/bin/env python

# global imports
import os

import numpy as np
import json
import flask
import flask_graphql
from flask_cors import CORS
import logging
from raven.contrib.flask import Sentry
# local imports
import models
import api
import warnings
from sqlalchemy.exc import OperationalError
# import qmdb_api

try:
    from apps.pourbaix.run_pourbaix import pourbaix
except ImportError:
    warnings.warn('pourbaix diagrams not available.')
    pourbaix = None

try:
    from apps.catlearn.run_catlearn import catlearn_blueprint
except ImportError:
    warnings.warn('Catlearn not available.')
    atoml_blueprint = None

try:
    from apps.activityMaps import activityMaps
except ImportError:
    warnings.warn('activityMaps not available.')
    activityMaps = None

try:
    from apps.prototypeSearch import app as prototypeSearch
except (ImportError, OperationalError):
    warnings.warn('prototypeSearch not available.')
    prototypeSearch = None

try:
    from apps.bulkEnumerator import bulk_enumerator
except ImportError:
    warnings.warn('prototypeSearch not available.')
    bulk_enumerator = None

try:
    from apps.catKitDemo import catKitDemo
except ImportError:
    warnings.warn('catKitDemo not available.')
    catKitDemo = None


# NumpyEncoder: useful for JSON serializing
# Dictionaries that contain Numpy Arrays
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return super(NumpyEncoder, self).default(obj)


app = flask.Flask(__name__)

app.debug = False

if not app.debug:
    sentry = Sentry(app, logging=True, level=logging.DEBUG)

app.json_encoder = NumpyEncoder

cors = CORS(app, supports_credentials=True)

# , resources={r"/graphql/*":
#    {"origins":
#        ["localhost:.*",
#            "catapp-browser.herokuapp.com",
#            "*"

#            ]
#        }
#    }
#    )


@app.route('/')
def index():
    return flask.redirect(
            "/graphql?query=%7B%0A%20%20reactions(first%3A%2010)%20%7B%0A%20%20%20%20edges%20%7B%0A%20%20%20%20%20%20node%20%7B%0A%20%20%20%20%20%20%20%20Equation%0A%20%20%20%20%20%20%20%20chemicalComposition%0A%20%20%20%20%20%20%20%20reactionEnergy%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A%20%20%7D%0A%7D%0A",
            code=302)


@app.route('/apps/')
def apps():
    return "Apps: catlearn, pourbaix"


if bulk_enumerator is not None:
    app.register_blueprint(bulk_enumerator, url_prefix='/apps/bulkEnumerator')
if catKitDemo is not None:
    app.register_blueprint(catKitDemo, url_prefix='/apps/catKitDemo')


from apps.upload import upload
app.register_blueprint(upload, url_prefix='/apps/upload')

# Graphql view
app.add_url_rule('/graphql',
                 view_func=flask_graphql.GraphQLView.as_view(
                         'graphql',
                         schema=api.schema,
                         graphiql=True,
                         context={'session': models.db_session}
                         )
                 )

# Graphql view
# app.add_url_rule('/qmdb_graphql',
#        view_func=flask_graphql.GraphQLView.as_view(
#            'qmdb_graphql',
#            schema=qmdb_api.schema,
#            graphiql=True,
#            context={
#                'session': qmdb_api.db_session,
#                }
#            )
#        )


if pourbaix is not None:
    app.register_blueprint(pourbaix, url_prefix='/apps/pourbaix')
if activityMaps is not None:
    app.register_blueprint(activityMaps,  url_prefix='/apps/activityMaps')
if prototypeSearch is not None:
    app.register_blueprint(prototypeSearch, url_prefix='/apps/prototypeSearch')
if catlearn_blueprint is not None:
    app.register_blueprint(catlearn_blueprint, url_prefix='/apps/catlearn')


if __name__ == '__main__':
    import optparse

    parser = optparse.OptionParser()
    parser.add_option('-s',
                      '--debug-sql',
                      help="Print executed SQL statement to commandline",
                      dest="debug_sql",
                      action="store_true",
                      default=False)

    options, args = parser.parse_args()

    if options.debug_sql:
        import logging
        logging.basicConfig()
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(64)
    app.run()
