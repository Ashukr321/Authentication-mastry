export type NavTopic = { number: string; title: string; href: string; done: boolean };

export type NavLevel = {
    number: number;
    title: string;
    href: string;
    topics: NavTopic[];
};

/** One entry of /search-index.json: a topic, or a section inside a topic. */
export type SearchItem = {
    title: string;
    context: string;
    href: string;
    soon?: boolean;
};
