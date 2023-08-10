from db import db


class BlockListModel(db.Model):
    __tablename__ = "blocklist"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    revoked_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, jti, revoked_on):
        self.jti = jti
        self.revoked_on = revoked_on


