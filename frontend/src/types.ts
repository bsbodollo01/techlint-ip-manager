export type Role = 'regular' | 'super_admin';

export interface User {
  id: number;
  email: string;
  role: Role;
}

export interface IpRecord {
  id: number;
  ip: string;
  label: string;
  comment: string;
  owner_user_id: number;
  owner_email: string;
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: number;
  event_type: string;
  actor_user_id: number | null;
  actor_email: string | null;
  session_id: string | null;
  target_type: string;
  target_id: number | null;
  details: string;
  created_at: string;
}
