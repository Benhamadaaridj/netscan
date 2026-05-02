#!/usr/bin/env python
from app import create_app
from app.scheduler import start_scheduler
import os

app = create_app()

# Start the scheduler 
start_scheduler(app)

if __name__ == '__main__':
    debug = os.environ.get('FLASK_ENV', 'development') == 'development'
    port = int(os.environ.get('PORT', 5000))

    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)