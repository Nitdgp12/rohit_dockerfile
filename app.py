# Install required packages using: pip install Flask Flask-RESTful Flask-JWT-Extended

from flask import Flask, request
from flask_restful import Resource, Api
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in a production environment
api = Api(app)
jwt = JWTManager(app)

# Mock user data (for simplicity)
users = {
    'user1': {'password': 'password1'},
    'user2': {'password': 'password2'}
}

# Mock task data (for simplicity)
tasks = {
    'user1': [],
    'user2': []
}

# Resource for task manipulation
class TaskResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return tasks.get(current_user, [])

    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        new_task = {'task': data['task']}
        tasks[current_user].append(new_task)
        return {'message': 'Task added successfully', 'task': new_task}

    @jwt_required()
    def put(self, task_id):
        current_user = get_jwt_identity()
        data = request.get_json()
        tasks[current_user][task_id] = {'task': data['task']}
        return {'message': 'Task updated successfully', 'task': tasks[current_user][task_id]}

    @jwt_required()
    def delete(self, task_id):
        current_user = get_jwt_identity()
        deleted_task = tasks[current_user].pop(task_id, None)
        if deleted_task:
            return {'message': 'Task deleted successfully', 'task': deleted_task}
        else:
            return {'message': 'Task not found'}, 404

# Resource for user authentication
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username in users and users[username]['password'] == password:
            access_token = create_access_token(identity=username)
            return {'access_token': access_token}
        else:
            return {'message': 'Invalid credentials'}, 401

# Adding resources to the API
api.add_resource(TaskResource, '/tasks', '/tasks/<int:task_id>')
api.add_resource(UserLogin, '/login')

if __name__ == '__main__':
    app.run(debug=True)

