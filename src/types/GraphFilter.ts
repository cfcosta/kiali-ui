import PropTypes from 'prop-types';
import Namespace from './Namespace';

export interface GraphFilterProps {
  disabled: boolean;
  onLayoutChange: (newLayout: Layout) => void;
  onFilterChange: (newDuration: Duration) => void;
  onNamespaceChange: (newValue: Namespace) => void;
  onBadgeStatusChange: (newValue: BadgeStatus) => void;
  onRefresh: () => void;
  onError: PropTypes.func;
  activeNamespace: Namespace;
  activeLayout: Layout;
  activeDuration: Duration;
  activeBadgeStatus: BadgeStatus;
}

export interface GraphFilterState {
  availableNamespaces: { name: string }[];
}

export interface Layout {
  name: string;
}

export interface Duration {
  value: string;
}

export interface BadgeStatus {
  hideCBs: boolean;
}
