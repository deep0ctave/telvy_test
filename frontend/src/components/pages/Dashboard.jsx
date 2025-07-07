import React, { useEffect, useState } from 'react';
import {
  Loader2,
  BookOpen,
  ClipboardList,
  UserCircle,
  Star,
  Timer,
  Users,
  ListChecks,
  ListTodo,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

const Dashboard = () => {
  const { user: rawUser, loading } = useAuth();
  const user = rawUser?.user || rawUser;
  const [stats, setStats] = useState(null);

  useEffect(() => {
    // Mock stats fetch — replace with real API calls later
    setTimeout(() => {
      setStats({
        quizzesCreated: 6,
        questionsAdded: 42,
        studentsAttempted: 87,

        attemptsMade: 12,
        questionsAttempted: 75,
        averageScore: 82,
        timeSpent: '3h 45m',

        totalUsers: 250,
        totalStudents: 180,
        totalTeachers: 70,
        totalQuestions: 420,
        totalQuizzes: 98,
      });
    }, 500);
  }, []);

  const isStudent = user?.user_type === 'student';
  const isTeacher = user?.user_type === 'teacher';
  const isAdmin = user?.user_type === 'admin';

  if (loading || !user || !stats) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  const StatCard = ({ icon: Icon, label, value, color = 'text-primary' }) => (
    <div className="card bg-base-200 shadow-md">
      <div className="card-body flex items-center gap-4">
        <Icon className={`w-8 h-8 ${color}`} />
        <div>
          <p className="text-sm text-gray-500">{label}</p>
          <p className="text-xl font-semibold">{value}</p>
        </div>
      </div>
    </div>
  );

  return (
    <div className="p-6 space-y-6">
      {/* Profile Card */}
      <div className="card shadow-xl bg-base-100 border border-base-300">
        <div className="card-body flex flex-col md:flex-row gap-6 items-center">
          <div className="avatar">
            <div className="w-24 rounded-full ring ring-primary ring-offset-base-100 ring-offset-2">
              <img src={`https://api.dicebear.com/7.x/thumbs/svg?seed=${user.username}`} alt="avatar" />
            </div>
          </div>
          <div className="flex-1 space-y-1 text-center md:text-left">
            <h2 className="text-2xl font-bold">{user.name}</h2>
            <p className="text-sm opacity-80">
              {user.username} • {user.email}
            </p>
            {isStudent && (
              <p className="text-sm text-gray-500">
                {user.school} • Class {user.class} - {user.section}
              </p>
            )}
            <span className="badge badge-outline capitalize mt-2">
              {user.user_type}
            </span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {isTeacher && (
          <>
            <StatCard icon={BookOpen} label="Quizzes Created" value={stats.quizzesCreated} />
            <StatCard icon={ClipboardList} label="Questions Added" value={stats.questionsAdded} color="text-success" />
            <StatCard icon={Users} label="Students Attempted" value={stats.studentsAttempted} color="text-warning" />
          </>
        )}

        {isStudent && (
          <>
            <StatCard icon={UserCircle} label="Quiz Attempts" value={stats.attemptsMade} color="text-info" />
            <StatCard icon={ListChecks} label="Questions Attempted" value={stats.questionsAttempted} color="text-success" />
            <StatCard icon={Star} label="Success Rate" value={`${stats.averageScore}%`} color="text-yellow-500" />
            <StatCard icon={Timer} label="Time Spent" value={stats.timeSpent} color="text-purple-500" />
          </>
        )}

        {isAdmin && (
          <>
            <StatCard icon={Users} label="Total Users" value={stats.totalUsers} />
            <StatCard icon={UserCircle} label="Total Students" value={stats.totalStudents} color="text-info" />
            <StatCard icon={UserCircle} label="Total Teachers" value={stats.totalTeachers} color="text-accent" />
            <StatCard icon={ListTodo} label="Total Questions" value={stats.totalQuestions} color="text-success" />
            <StatCard icon={BookOpen} label="Total Quizzes" value={stats.totalQuizzes} color="text-warning" />
          </>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
