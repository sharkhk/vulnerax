from marshmallow import Schema, fields

class CVESchema(Schema):
    id = fields.Str()
    description = fields.Str()
    publishedDate = fields.Str()
    lastModifiedDate = fields.Str()
    cvssScore = fields.Float(allow_none=True)
