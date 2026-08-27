import sqlite3

DB_NAME = "case_database.db"

def insert_event(event_dict):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO normalized_event (
            event_id, timestamp_utc, category, subcategory, 
            actor_user, source_ip, event_kind, description, 
            source_artifact_path, parser_name, parser_version, raw_evidence_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_dict.get('event_id'),
        event_dict.get('timestamp_utc'),
        event_dict.get('category', 'identity_access'),
        event_dict.get('subcategory'),
        event_dict.get('actor_user'),
        event_dict.get('source_ip'),
        event_dict.get('event_kind', 'event'),
        event_dict.get('description'),
        event_dict.get('source_artifact_path'),
        event_dict.get('parser_name'),
        event_dict.get('parser_version', '1.0'),
        event_dict.get('raw_evidence_hash')
    ))
    conn.commit()
    conn.close()