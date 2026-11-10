// Imported only by the local Vite browser harness; excluded from portal builds.
import '../../apps/portal/src/portal.css';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { ProtectedReports } from '../../apps/portal/src/ProtectedReports';
export function mountProtected(props: {
  accountId: string;
  csrf: string;
  role: string;
  enabled: boolean;
  intakeEnabled: boolean;
}) {
  const container = document.createElement('main');
  document.body.append(container);
  const root = createRoot(container);
  root.render(<ProtectedReports {...props} />);
  return () => root.unmount();
}
