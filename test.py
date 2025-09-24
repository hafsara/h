def update_application(app_id):
    """
    Update an application's name, token (if required), and mail sender.
    """
    data = request.json

    try:
        validated_data = application_update_schema.load(data)
    except ValidationError as err:
        return error_response(err.messages, 400)

    application = Application.query.filter_by(id=app_id).first_or_404()
    old_app_id = application.id
    old_name = application.name
    generate_new_id = validated_data.get("generate_new_id", False)

    try:
        if "name" in validated_data and validated_data["name"] != application.name:
            new_name = validated_data["name"]
            existing_app = Application.query.filter_by(name=new_name).first()
            if existing_app and existing_app.id != application.id:
                return error_response("Application name already exists", 400)

        db.session.begin_nested()

        if "name" in validated_data and validated_data["name"] != application.name:
            new_name = validated_data["name"]
            application.name = new_name

            # Update app_names in API tokens
            api_tokens = APIToken.query.filter(APIToken.app_names.contains([old_name])).all()
            for token in api_tokens:
                token.app_names = [new_name if name == old_name else name for name in token.app_names]
            db.session.bulk_save_objects(api_tokens)

        if "new_mail_sender" in validated_data and application.mail_sender != validated_data["new_mail_sender"]:
            application.mail_sender = validated_data["new_mail_sender"]

        if "exposed" in validated_data:
            application.exposed = validated_data["exposed"]

        new_app_id = None
        if generate_new_id:
            new_app_id = str(uuid.uuid4())

            while Application.query.filter_by(id=new_app_id).first():
                new_app_id = str(uuid.uuid4())
            FormContainer.query.filter_by(app_id=old_app_id).update({"app_id": new_app_id})
            Campaign.query.filter_by(app_id=old_app_id).update({"app_id": new_app_id})
            EmailTemplate.query.filter_by(app_token=old_app_id).update({"app_token": new_app_id})
            application.id = new_app_id

        db.session.commit()
        redis_key_id = new_app_id if generate_new_id else old_app_id
        if "name" in validated_data or generate_new_id:
            redis_client.setex(f"app:changed:{redis_key_id}", 60, "modified")

        return jsonify({
            "message": "Application updated successfully",
            "app_token": application.id,
            "new_app_id": new_app_id if generate_new_id else None
        }), 200

    except IntegrityError as e:
        db.session.rollback()
        return error_response("Integrity error: possible duplicate name or ID", 400)
    except SQLAlchemyError as e:
        db.session.rollback()
        return error_response("Database update failed: " + str(e), 500)
