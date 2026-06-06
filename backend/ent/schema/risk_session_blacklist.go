package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RiskSessionBlacklist stores persistently blocked risk-control sessions.
type RiskSessionBlacklist struct {
	ent.Schema
}

func (RiskSessionBlacklist) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "risk_session_blacklists"},
	}
}

func (RiskSessionBlacklist) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (RiskSessionBlacklist) Fields() []ent.Field {
	return []ent.Field{
		field.String("session_hash").NotEmpty(),
		field.Int64("user_id").Optional().Nillable(),
		field.Int64("api_key_id").Optional().Nillable(),
		field.Int64("group_id").Optional().Nillable(),
		field.Text("reason").Default(""),
		field.JSON("categories", []string{}).
			Optional().
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.Float("confidence").Default(0),
		field.String("audit_model").Default(""),
		field.String("audit_response_id").Default(""),
		field.String("source_protocol").Default(""),
		field.String("source_model").Default(""),
		field.Time("first_blocked_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("last_seen_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("expires_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
	}
}

func (RiskSessionBlacklist) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("session_hash").Unique(),
		index.Fields("user_id"),
		index.Fields("api_key_id"),
		index.Fields("group_id"),
		index.Fields("expires_at"),
		index.Fields("last_seen_at"),
	}
}
