export type CapabilityMode = 'live' | 'demo' | 'unavailable';

export type Capability = {
  mode: CapabilityMode;
  label: string;
  explanation: string;
};

export const capabilities = {
  platformOrganizations: { mode: 'live', label: 'Live', explanation: 'Shared-host organization creation and organizer invitation use the platform API. Email requires an approved transport.' },
  platformOrganizationDirectory: { mode: 'live', label: 'Live', explanation: 'Organization search, pagination, and details use the MFA-protected platform API.' },
  platformPrivacy: { mode: 'unavailable', label: 'Coming soon', explanation: 'Privacy notice management is currently unavailable.' },
  platformOverview: { mode: 'unavailable', label: 'Limited data', explanation: 'Platform-wide aggregate APIs are planned for M6. The console shows only live readiness currently returned by the service.' },
  platformOperations: { mode: 'unavailable', label: 'Limited data', explanation: 'Queue, delivery, incident, and provider monitoring require authoritative telemetry APIs planned for M6.' },
  subscriptions: { mode: 'unavailable', label: 'Not connected', explanation: 'Billing terms and M2-02 APIs are not implemented.' },
  events: { mode: 'live', label: 'Live', explanation: 'Event configuration uses the current tenant APIs.' },
  branding: { mode: 'live', label: 'Live', explanation: 'Branding draft, preview and publication are connected.' },
  registration: { mode: 'live', label: 'Live', explanation: 'Public registration uses the verified tenant hostname.' },
  tickets: { mode: 'live', label: 'Live', explanation: 'Bulk issuance, queued delivery, and individual credential commands use authorized APIs.' },
  organizerOverview: { mode: 'live', label: 'Live', explanation: 'Workspace attendance uses confirmed server records.' },
  attendees: { mode: 'live', label: 'Live', explanation: 'The participant directory is event-scoped and server-authorized.' },
  import: { mode: 'live', label: 'Live', explanation: 'Bulk imports are validated and committed through tenant-scoped background jobs.' },
  checkin: { mode: 'live', label: 'Live', explanation: 'Attendance is calculated from server-confirmed ticket redemptions.' },
  communications: { mode: 'unavailable', label: 'Coming soon', explanation: 'Campaign sending and provider callbacks require M5.' },
  reports: { mode: 'live', label: 'Live', explanation: 'Basic event attendance export is server-authorized.' },
  team: { mode: 'live', label: 'Live', explanation: 'Scoped gate-staff invitations use the current authorized API.' },
  gate: { mode: 'live', label: 'Live', explanation: 'Gate results require an assigned session and atomic server redemption.' },
} as const satisfies Record<string, Capability>;
