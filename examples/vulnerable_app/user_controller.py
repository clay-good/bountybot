"""
Example vulnerable user controller for testing bountybot.
This code contains intentional vulnerabilities for demonstration purposes.
DO NOT USE IN PRODUCTION.
"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


class UserController:
    """User management controller with SQL injection vulnerability."""
    
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
    
    def search(self, query):
        """
        Search for users by name.
        VULNERABLE: Uses string concatenation for SQL query construction.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: SQL injection through string concatenation
        sql = "SELECT * FROM users WHERE name LIKE '%" + query + "%'"
        cursor.execute(sql)
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def get_user_by_id(self, user_id):
        """
        Get user by ID.
        SECURE: Uses parameterized query.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # SECURE: Parameterized query
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result


@app.route('/api/users/search', methods=['POST'])
def search_users():
    """
    API endpoint for user search.
    VULNERABLE: Passes unsanitized input to search method.
    """
    data = request.get_json()
    query = data.get('query', '')
    
    # No input validation or sanitization
    controller = UserController()
    results = controller.search(query)
    
    return jsonify({'users': results})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """
    API endpoint to get user by ID.
    SECURE: Uses parameterized query through controller.
    """
    controller = UserController()
    result = controller.get_user_by_id(user_id)
    
    if result:
        return jsonify({'user': result})
    else:
        return jsonify({'error': 'User not found'}), 404


if __name__ == '__main__':
    app.run(debug=True)

