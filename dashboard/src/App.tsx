import { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Overview } from './views/Overview';
import { RequestFeed } from './views/RequestFeed';
import { Credentials } from './views/Credentials';
import { Agents } from './views/Agents';
import { BlockedRequests } from './views/BlockedRequests';
import { Users } from './views/Users';

export type View = 'overview' | 'requests' | 'credentials' | 'agents' | 'users' | 'blocked';

export function App(): React.ReactElement {
  const [currentView, setCurrentView] = useState<View>('overview');

  function renderView(): React.ReactElement {
    switch (currentView) {
      case 'overview':
        return <Overview />;
      case 'requests':
        return <RequestFeed />;
      case 'credentials':
        return <Credentials />;
      case 'agents':
        return <Agents />;
      case 'users':
        return <Users />;
      case 'blocked':
        return <BlockedRequests />;
    }
  }

  return (
    <div className="flex h-screen bg-surface-0 text-primary">
      <Sidebar currentView={currentView} onNavigate={setCurrentView} />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header currentView={currentView} />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto" style={{ maxWidth: 'var(--content-max-width)' }}>
            {renderView()}
          </div>
        </main>
      </div>
    </div>
  );
}
