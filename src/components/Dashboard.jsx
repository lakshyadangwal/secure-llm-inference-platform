import React from 'react';
import { motion } from 'framer-motion';
import StatusCard from './StatusCard';
import StatsGrid from './StatsGrid';

const Dashboard = ({ isDefending, isProcessing, isBreached, stats }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="h-full overflow-y-auto scrollbar-hide"
    >
      <StatusCard isDefending={isDefending} isProcessing={isProcessing} isBreached={isBreached} />
      <StatsGrid stats={stats} />
    </motion.div>
  );
};

export default Dashboard;
