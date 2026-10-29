import { ComingSoonState, PageHeader } from './components';

export function PrivacyNotices() {
  return <><PageHeader eyebrow="Platform console" title="Privacy notices" description="Privacy notice management" />
    <ComingSoonState title="Privacy notices are coming soon" description="Notice drafting, approval, and activation are currently unavailable. Organizers do not need to configure a notice to import participants or open registration." />
  </>;
}
