export default function Loading() {
    return (
        <div className="px-5 py-10 sm:px-8 lg:px-12" aria-busy="true" aria-label="Loading">
            <div className="h-4 w-40 animate-pulse rounded bg-hover" />
            <div className="mt-4 h-10 w-2/3 animate-pulse rounded bg-hover" />
            <div className="mt-8 space-y-3">
                {[100, 92, 96, 80].map((w) => (
                    <div key={w} className="h-4 animate-pulse rounded bg-hover" style={{ width: `${w}%` }} />
                ))}
            </div>
        </div>
    );
}
