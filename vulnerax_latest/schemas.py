from marshmallow import Schema, fields

class CVEQuerySchema(Schema):
    days = fields.Int(missing=1)
    limit = fields.Int(missing=50)

class CVESchema(Schema):
    id = fields.Str()
    description = fields.Str()
    publishedDate = fields.Str()
    lastModifiedDate = fields.Str()
    cvssScore = fields.Float(allow_none=True)
