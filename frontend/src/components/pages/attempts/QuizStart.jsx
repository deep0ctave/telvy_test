// File: QuizStart.jsx
import React from 'react';
import { useNavigate, useParams, useLocation } from 'react-router-dom';
import { CalendarDays, Clock10, Tags, CircleUser } from 'lucide-react';

const QuizStart = () => {
  const { quizId } = useParams();
  const { state } = useLocation();
  const navigate = useNavigate();
  const quiz = state?.quiz;

  if (!quiz) {
    return <div className="p-6">Quiz not found or data missing.</div>;
  }

  const now = new Date();
  const startsAt = new Date(quiz.starts_at || Date.now()); // fallback to now
  const endsAt = new Date(quiz.ends_at || Date.now() + quiz.duration_minutes * 60 * 1000);
  const isFuture = startsAt > now;

  const getButtonLabel = () => {
    if (quiz.status === "scheduled" && isFuture) return "Scheduled";
    if (quiz.status === "not_started") return "Start Quiz";
    if (quiz.status === "ongoing") return "Continue Quiz";
    if (quiz.status === "completed") return "Review Quiz";
    return "Unavailable";
  };

  const isButtonDisabled = () => {
    return quiz.status === "scheduled" && isFuture;
  };

  const handleClick = () => {
    if (quiz.status === "not_started") {
      navigate(`/attempts/live/${quiz.id}`);
    } else if (quiz.status === "ongoing") {
      navigate(`/attempts/live/${quiz.attempt_id}`);
    } else if (quiz.status === "completed") {
      navigate(`/attempts/result/${quiz.attempt_id}`);
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-3xl mx-auto space-y-4">
      <div className="card bg-base-100 border border-base-300 shadow-md overflow-hidden">
        {quiz.image_url && (
          <img
            src={quiz.image_url}
            alt={quiz.title}
            className="w-full h-52 object-cover"
          />
        )}
        <div className="card-body p-4 space-y-3">
          <h2 className="text-xl font-bold">{quiz.title}</h2>
          <p className="text-sm text-base-content/70">{quiz.description}</p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm mt-2">
            <div className="flex items-center gap-2">
              <Clock10 className="w-4 h-4 text-primary" />
              <span>{quiz.duration_minutes} mins</span>
            </div>
            <div className="flex items-center gap-2">
              <CalendarDays className="w-4 h-4 text-primary" />
              <span>
                {startsAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} -{" "}
                {endsAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <CircleUser className="w-4 h-4 text-primary" />
              <span className="capitalize">{quiz.quiz_type || "mcq"}</span>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <Tags className="w-4 h-4 text-primary" />
              <div className="flex gap-1 flex-wrap">
                {quiz.tags.map((tag, i) => (
                  <div key={i} className="badge badge-outline badge-sm">
                    {tag}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="alert alert-info text-xs sm:text-sm mt-4">
            {quiz.status === "not_started"
              ? "Once you start the quiz, the timer will begin. Do not refresh or leave."
              : quiz.status === "ongoing"
              ? "You can resume your quiz attempt."
              : quiz.status === "completed"
              ? "You have completed this quiz. View your results."
              : "This quiz is scheduled to begin soon."}
          </div>

          <div className="flex justify-end">
            <button
              className="btn btn-primary btn-md sm:btn-md mt-2"
              onClick={handleClick}
              disabled={isButtonDisabled()}
            >
              {getButtonLabel()}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuizStart;
