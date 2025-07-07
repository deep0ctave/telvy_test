// File: components/pages/Student/Quizzes.jsx

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../../context/AuthContext";

const mockQuizzes = [
  {
    id: 1,
    title: "Math Quiz",
    description: "Algebra & Arithmetic",
    tags: ["math"],
    status: "not_started",
    attempt_id: null,
    questions_count: 10,
    duration_minutes: 15,
  },
  {
    id: 2,
    title: "Science Basics",
    description: "Physics and Chemistry",
    tags: ["science"],
    status: "completed",
    attempt_id: 301,
    questions_count: 12,
    duration_minutes: 20,
  },
  {
    id: 3,
    title: "Current Affairs",
    description: "GK for July",
    tags: ["gk"],
    status: "ongoing",
    attempt_id: 302,
    questions_count: 8,
    duration_minutes: 10,
  },
];

const Quizzes = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const currentUser = user?.user || user;

  const [quizzes, setQuizzes] = useState([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    setTimeout(() => setQuizzes(mockQuizzes), 300);
  }, []);

  const filtered = quizzes.filter((quiz) =>
    quiz.title.toLowerCase().includes(search.toLowerCase())
  );

  const handleNavigate = (quiz) => {
    navigate(`/attempts/start/${quiz.id}`, { state: { quiz } });
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Available Quizzes</h1>

      <input
        type="text"
        className="input input-bordered w-64"
        placeholder="Search quizzes..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.length === 0 ? (
          <p className="text-base-content/60">No quizzes found.</p>
        ) : (
          filtered.map((quiz) => (
            <div
              key={quiz.id}
              className="card bg-base-100 border shadow-sm hover:shadow-md transition"
            >
              <div className="card-body space-y-2">
                <h2 className="card-title">{quiz.title}</h2>
                <p className="text-sm text-base-content/70">{quiz.description}</p>

                <div className="text-sm text-base-content/70">
                  <p>Questions: {quiz.questions_count}</p>
                  <p>Time: {quiz.duration_minutes} min</p>
                </div>

                <div className="flex flex-wrap gap-1">
                  {quiz.tags.map((tag) => (
                    <span key={tag} className="badge badge-outline badge-sm">
                      {tag}
                    </span>
                  ))}
                </div>

                <div className="flex justify-between items-center pt-2">
                  <span
                    className={`badge text-xs ${
                      quiz.status === "completed"
                        ? "badge-success"
                        : quiz.status === "ongoing"
                        ? "badge-info"
                        : quiz.status === "scheduled"
                        ? "badge-warning"
                        : "badge-neutral"
                    }`}
                  >
                    {quiz.status.replace("_", " ")}
                  </span>

                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => handleNavigate(quiz)}
                  >
                    {quiz.status === "completed"
                      ? "Review"
                      : quiz.status === "ongoing"
                      ? "Continue"
                      : "Start"}
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Quizzes;
