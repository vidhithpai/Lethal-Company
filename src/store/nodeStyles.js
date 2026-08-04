import * as THREE from 'three';

export const NODE_TYPES = {
  SOURCE: 'source',
  SINK: 'sink',
  SANITIZER: 'sanitizer',
  FUNCTION: 'function',
  INTERMEDIATE: 'intermediate',
  NORMAL: 'normal'
};

export const NODE_STYLE_LOOKUP = {
  [NODE_TYPES.SOURCE]: {
    baseRadius: 6,
    geometry: (radius) => new THREE.SphereGeometry(radius, 16, 16),
    color: '#10B981',
    label: 'Entry / Source (Input)'
  },
  [NODE_TYPES.SINK]: {
    baseRadius: 9,
    geometry: (radius) => new THREE.IcosahedronGeometry(radius, 0),
    color: '#EF4444',
    label: 'Sensitive Sink (Op)'
  },
  [NODE_TYPES.SANITIZER]: {
    baseRadius: 7,
    geometry: (radius) => new THREE.CylinderGeometry(radius, radius, radius * 1.5, 6),
    color: '#8B5CF6',
    label: 'Security Guard (Filter)'
  },
  [NODE_TYPES.FUNCTION]: {
    baseRadius: 5,
    geometry: (radius) => new THREE.BoxGeometry(radius * 1.6, radius * 1.6, radius * 1.6),
    color: '#3B82F6',
    label: 'Application Logic'
  },
  [NODE_TYPES.INTERMEDIATE]: {
    baseRadius: 4.5,
    geometry: (radius) => new THREE.OctahedronGeometry(radius, 0),
    color: '#F59E0B',
    label: 'Decision / Intermediate'
  },
  [NODE_TYPES.NORMAL]: {
    baseRadius: 3.5,
    geometry: (radius) => new THREE.SphereGeometry(radius, 16, 16),
    color: '#9CA3AF',
    label: 'Normal Node'
  }
};

export const getBaseNodeStyle = (type) => {
  const normalizedType = String(type || '').toLowerCase();
  return NODE_STYLE_LOOKUP[normalizedType] || NODE_STYLE_LOOKUP[NODE_TYPES.NORMAL];
};

export const getNodeSize = (node) => {
  const style = getBaseNodeStyle(node.type);
  let radius = style.baseRadius;
  
  if (node.modified) {
    radius *= 1.2;
  }
  return radius;
};
