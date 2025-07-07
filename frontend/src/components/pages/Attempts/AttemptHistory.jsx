import React, { useEffect, useState } from 'react';
import { useAuth } from '../../../context/AuthContext';
import { Loader2 } from 'lucide-react';
import { Link } from 'react-router-dom';

const AttemptHistory = () => {
  const { user } = useAuth();
  const [attempts, setAttempts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // TODO: Replace with actual API call
    setTimeout(() => {
      setAttempts([
        {
          id: 1,
          quizTitle: 'Physics Basics',
          score: 8,
          total: 10,
          submittedAt: '2025-07-01T14:32:00Z',
        },
        {
          id: 2,
          quizTitle: 'Math Fundamentals',
          score: 5,
          total: 10,
          submittedAt: '2025-06-28T10:00:00Z',
        },
      ]);
      setLoading(false);
    }, 1000);
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-[50vh]">
        <Loader2 className="animate-spin w-6 h-6 text-primary" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Your Quiz Attempts</h1>

      {attempts.length === 0 ? (
        <div className="alert alert-info shadow-sm">
          <span>No quiz attempts found yet. Go take your first quiz!</span>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {attempts.map((attempt) => (
            <div key={attempt.id} className="card bg-base-100 shadow-md border">
              <div className="card-body">
                <h2 className="card-title text-lg">{attempt.quizTitle}</h2>
                <p>
                  <span className="font-semibold">Score:</span> {attempt.score}/{attempt.total}
                </p>
                <p className="text-sm text-gray-500">
                  Submitted: {new Date(attempt.submittedAt).toLocaleString()}
                </p>
                <div className="mt-4">
                  <Link
                    to={`/attempts/result/${attempt.id}`}
                    className="btn btn-sm btn-primary"
                  >
                    View Result
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AttemptHistory;
