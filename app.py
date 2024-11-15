from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from pymongo import MongoClient
import os
import uuid
import shutil 
from datetime import datetime
import mimetypes
import hashlib


app = Flask(__name__)
app.secret_key = "supersecretkey"

mongo_uri = "mongodb://127.0.0.1:27017/5000?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+2.3.3"
client = MongoClient(mongo_uri)
db = client['Lakshmeesh']
collection = db['upload']

LOCAL_STORAGE_BASE = 'local_storage'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        tenant_id = request.form.get('tenantId')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if tenant_id and username and password:  
            # Check if credentials match any document in MongoDB
            user_data = collection.find_one({
                "tenantId": tenant_id,
                "users": {
                    "$elemMatch": {
                        "username": username,
                        "password": password
                    }
                }
            })

            if user_data:
                # Login successful
                session['tenantId'] = tenant_id
                session['username'] = username
                flash("Logged in successfully!", "success")
                return redirect(url_for('workspace'))
            else:
                # Login failed
                flash("Login failed. Please check your credentials.", "error")

    return render_template('index.html')


@app.route('/workspace', methods=['GET', 'POST'])
def workspace():
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        flash("Session expired, please log in again.", "error")
        return redirect(url_for('index'))

    user_data = collection.find_one(
        {
            "tenantId": tenant_id,
            "users.username": user_name
        },
        {"users.$": 1}
    )

    workspaces = user_data['users'][0].get('workspaces', []) if user_data and 'users' in user_data else []

    if request.method == 'POST':
        workspace_name = request.form.get('workspace_name')
        if workspace_name:
            if any(w['workspaceName'] == workspace_name for w in workspaces):
                flash('Workspace already exists', 'error')
            else:
                new_workspace = {
                    "workspaceUUID": str(uuid.uuid4()),
                    "workspaceName": workspace_name,
                    "folders": [
                        {"folderName": "endoc", "contents": []},
                        {"folderName": "ensight", "contents": []},
                        {"folderName": "envision", "contents": []}
                    ]
                }

                result = collection.update_one(
                    {"tenantId": tenant_id},
                    {"$addToSet": {"users.$[user].workspaces": new_workspace}},
                    array_filters=[{"user.username": user_name}]
                )

                workspace_dir = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace_name)

                os.makedirs(workspace_dir, exist_ok=True)
                for folder in new_workspace['folders']:
                    folder_path = os.path.join(workspace_dir, folder['folderName'])
                    os.makedirs(folder_path, exist_ok=True)

                if result.modified_count > 0:
                    flash('Workspace created successfully!', 'success')
                    return redirect(url_for('folder', workspace_name=workspace_name))
                else:
                    flash('Failed to create workspace', 'error')

    return render_template('create_workspace.html', workspaces=workspaces)


@app.route('/delete_workspace/<workspace_uuid>', methods=['POST'])
def delete_workspace(workspace_uuid):
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        flash("Session expired, please log in again.", "error")
        return redirect(url_for('index'))

    # Check if workspace exists for this user
    user_data = collection.find_one(
        {
            "tenantId": tenant_id,
            "users.username": user_name,
            "users.workspaces.workspaceUUID": workspace_uuid
        },
        {"users.$": 1}
    )

    if not user_data:
        flash('Workspace does not exist', 'error')
        return redirect(url_for('workspace'))

    # Get workspace name to construct the local path
    workspace_name = next((w['workspaceName'] for w in user_data['users'][0]['workspaces'] if w['workspaceUUID'] == workspace_uuid), None)

    # Attempt to delete the workspace in MongoDB
    result = collection.update_one(
        {"tenantId": tenant_id, "users.username": user_name},
        {"$pull": {"users.$.workspaces": {"workspaceUUID": workspace_uuid}}}
    )

    # Construct local directory path
    workspace_dir = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace_name)

    # Remove local directory if it exists
    if os.path.exists(workspace_dir):
        try:
            shutil.rmtree(workspace_dir)
        except Exception as e:
            flash(f'Failed to delete local workspace directory: {str(e)}', 'error')

    if result.modified_count > 0:
        flash('Workspace deleted successfully', 'success')
    else:
        flash('Failed to delete workspace', 'error')

    return redirect(url_for('workspace'))

@app.route('/folder/<workspace_name>', methods=['GET', 'POST'])
def folder(workspace_name):
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        flash("Session expired, please log in again.", "error")
        return redirect(url_for('index'))

    return render_template('folder.html', workspace_name=workspace_name)


@app.route('/upload', methods=['POST'])
def upload_files():
    tenant_id = session.get('tenantId')
    user_name = session.get('username')
    workspace_name = request.form.get('workspace')
    folder_name = request.form.get('folder') 

    if not all([tenant_id, user_name, workspace_name, folder_name]):
        flash("Error: One or more required fields are missing.", "error")
        return redirect(url_for('folder', workspace_name=workspace_name))

    upload_folder = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace_name, folder_name)
    os.makedirs(upload_folder, exist_ok=True)  

    files = request.files.getlist('files')
    uploaded_files_metadata = []  # To store metadata for each uploaded file
    duplicate_files = []  # To keep track of any duplicate files
    uploaded_file_names = []  # To store names of successfully uploaded files
    duplicate_file_names = []  # To store names of duplicate files

    # Query to retrieve the document and filter out the hashes in the specified folder manually
    user_doc = collection.find_one({
        "tenantId": tenant_id,
        "users.username": user_name,
        "users.workspaces.workspaceName": workspace_name,
        "users.workspaces.folders.folderName": folder_name
    })

    # Extract the hashes if they exist in the returned document
    folder_hashes = []
    if user_doc:
        for user in user_doc.get("users", []):
            if user.get("username") == user_name:
                for workspace in user.get("workspaces", []):
                    if workspace.get("workspaceName") == workspace_name:
                        for folder in workspace.get("folders", []):
                            if folder.get("folderName") == folder_name:
                                folder_hashes = [
                                    content['hash'] for content in folder.get("contents", []) if "hash" in content
                                ]
                                break
    print("Hashes in selected folder:", folder_hashes)

    for file in files:
        # Calculate file hash (e.g., SHA-256) without saving the file first
        hash_sha256 = hashlib.sha256()
        for chunk in file.stream:
            hash_sha256.update(chunk)
        file_hash = hash_sha256.hexdigest()

        print("File hash:", file_hash)

        # Check if the hash already exists in the selected folder
        if file_hash in folder_hashes:
            # File is a duplicate
            duplicate_files.append(file)
            duplicate_file_names.append(file.filename)
            continue  # Skip saving this file

        # Reset file stream and save the file to the local storage since it's not a duplicate
        file.seek(0)
        file_path = os.path.join(upload_folder, file.filename)
        file.save(file_path)

        # Extract metadata for non-duplicate files
        file_metadata = {
            "filename": file.filename,
            "size": os.path.getsize(file_path),
            "upload_time": datetime.utcnow(),
            "mime_type": mimetypes.guess_type(file.filename)[0] or "application/octet-stream",
            "hash": file_hash,
            "creation_time": datetime.fromtimestamp(os.path.getctime(file_path)),
            "modification_time": datetime.fromtimestamp(os.path.getmtime(file_path)),
            "access_time": datetime.fromtimestamp(os.path.getatime(file_path))
        }
        uploaded_files_metadata.append(file_metadata)
        uploaded_file_names.append(file.filename)

    # If there are new files to upload (i.e., no duplicates), update MongoDB
    if uploaded_files_metadata:
        result = collection.update_one(
            {
                "tenantId": tenant_id,
                "users.username": user_name,
                "users.workspaces.workspaceName": workspace_name,
                "users.workspaces.folders.folderName": folder_name
            },
            {
                "$push": {
                    "users.$[user].workspaces.$[workspace].folders.$[folder].contents": {
                        "$each": uploaded_files_metadata
                    }
                }
            },
            array_filters=[
                {"user.username": user_name},
                {"workspace.workspaceName": workspace_name},
                {"folder.folderName": folder_name}
            ]
        )

        if result.modified_count > 0:
            flash("Files uploaded and metadata saved successfully!", "success")
        else:
            flash("Failed to save metadata in the database.", "error")

    if uploaded_file_names or duplicate_file_names:
        return redirect(url_for('upload_result', uploaded=uploaded_file_names, duplicates=duplicate_file_names))
    else:
        flash("No new files uploaded due to duplicates.", "info")
        return redirect(url_for('upload_duplicates'))


@app.route('/upload_result')
def upload_result():
    uploaded = request.args.getlist('uploaded')
    duplicates = request.args.getlist('duplicates')

    uploaded_files = ', '.join(uploaded) if uploaded else "None"
    duplicate_files = ', '.join(duplicates) if duplicates else "None"

    message = (
        "<span style='color: red;'>"
        "The file you're trying to upload already exists in the workspace. "
        "If you want to replace it with a new one, please use the update option."
        "</span>"
    )

    return f"""
        <p>Files uploaded successfully: {uploaded_files}</p><br><br><br>
        <p>Duplicate files: {duplicate_files}</p>
        <p>{message}</p>
    """



@app.route('/upload_duplicates')
def upload_duplicates():
    return "The file your trying to upload already exist in the workspace , if you want to replace it with a new one please use the update option."




@app.route('/list_files/<workspace>/<folder>', methods=['GET'])
def list_files(workspace, folder):
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        return jsonify({"error": "Session expired, please log in again."}), 403

    folder_path = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace, folder)
    if not os.path.exists(folder_path):
        return jsonify({"error": "Folder not found"}), 404

    files = os.listdir(folder_path)
    return jsonify({"files": files})


@app.route('/delete_file/<workspace>/<folder>/<file_name>', methods=['POST'])
def delete_file(workspace, folder, file_name):
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        return jsonify({"error": "Session expired, please log in again."}), 403

    
    folder_path = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace, folder)
    file_path = os.path.join(folder_path, file_name)

    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        
        os.remove(file_path)

        
        result = collection.update_one(
            {
                "tenantId": tenant_id,
                "users.username": user_name,
                "users.workspaces.workspaceName": workspace,
                "users.workspaces.folders.folderName": folder
            },
            {
                "$pull": {
                    "users.$[user].workspaces.$[workspace].folders.$[folder].contents": {"filename": file_name}
                }
            },
            array_filters=[
                {"user.username": user_name},
                {"workspace.workspaceName": workspace},
                {"folder.folderName": folder}
            ]
        )

        
        if result.modified_count > 0:
            return jsonify({"success": f"File '{file_name}' and its metadata deleted successfully."}), 200
        else:
            return jsonify({"error": "Failed to delete file metadata from database."}), 500

    except Exception as e:
        return jsonify({"error": f"Failed to delete file: {str(e)}"}), 500

@app.route('/update_file/<workspace>/<folder>/<file_name>', methods=['POST'])
def update_file(workspace, folder, file_name):
    tenant_id = session.get('tenantId')
    user_name = session.get('username')

    if not tenant_id or not user_name:
        return jsonify({"success": False, "error": "Session expired, please log in again."})

    folder_path = os.path.join(LOCAL_STORAGE_BASE, tenant_id, user_name, workspace, folder)
    old_file_path = os.path.join(folder_path, file_name)

    if 'new_file' not in request.files:
        return jsonify({"success": False, "error": "No file selected for update."})

    new_file = request.files['new_file']
    new_file_path = os.path.join(folder_path, new_file.filename)

    try:
        if os.path.exists(old_file_path):
            os.remove(old_file_path)
            collection.update_one(
                {
                    "tenantId": tenant_id,
                    "users.username": user_name,
                    "users.workspaces.workspaceName": workspace,
                    "users.workspaces.folders.folderName": folder
                },
                {
                    "$pull": {
                        "users.$[user].workspaces.$[workspace].folders.$[folder].contents": {"filename": file_name}
                    }
                },
                array_filters=[
                    {"user.username": user_name},
                    {"workspace.workspaceName": workspace},
                    {"folder.folderName": folder}
                ]
            )

        new_file.save(new_file_path)
        file_metadata = {
            "filename": new_file.filename,
            "size": os.path.getsize(new_file_path),
            "upload_time": datetime.utcnow(),
            "mime_type": mimetypes.guess_type(new_file.filename)[0] or "application/octet-stream",
            "hash": hashlib.sha256(open(new_file_path, 'rb').read()).hexdigest()
        }

        result = collection.update_one(
            {
                "tenantId": tenant_id,
                "users.username": user_name,
                "users.workspaces.workspaceName": workspace,
                "users.workspaces.folders.folderName": folder
            },
            {
                "$push": {
                    "users.$[user].workspaces.$[workspace].folders.$[folder].contents": file_metadata
                }
            },
            array_filters=[
                {"user.username": user_name},
                {"workspace.workspaceName": workspace},
                {"folder.folderName": folder}
            ]
        )

        if result.modified_count > 0:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Failed to update file metadata in MongoDB."})

    except Exception as e:
        return jsonify({"success": False, "error": f"Error updating file: {str(e)}"})





@app.route('/upload_success')
def upload_success():
    return "Files uploaded successfully!"


if __name__ == '__main__':
    os.makedirs(LOCAL_STORAGE_BASE, exist_ok=True)
    app.run(debug=True)
