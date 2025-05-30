from datetime import datetime
import json
from database.CompletedTutorials import CompletedTutorials
from database.Paths import Paths
from database.Tutorials import Tutorials
from database.Category import Category
from database.UserTutorialScore import UserTutorialScore
from database.Database import Database
from database.Account import AccountDatabase
from typing import Dict
import os
import requests
import base64


class TutorialService:
    @staticmethod
    def get_all_tutorials() -> list:
        """
        Récupérer la liste des tutoriels
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorials = tutorialDb.fetch_all()
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                tutorial_list.append(
                    {
                        "id": tutorial["id"],
                        "title": tutorial["title"],
                        "markdownUrl": tutorial["markdown_url"],
                        "category": tutorial["category"],
                        "answer": tutorial[
                            "answer"
                        ],  # if tutorial['should_be_check'] else None
                        "startCode": tutorial["start_code"],
                        "shouldBeCheck": tutorial["should_be_check"],
                        "enabled": tutorial["enabled"],
                        "points": tutorial["points"],
                        "inputs": tutorial["input"],
                        "default_language": tutorial["default_language"],
                        "image": tutorial["image"],
                        "short_description": tutorial["short_description"],
                        "estimated_time": tutorial["estimated_time"],
                        "path": tutorial["path"],
                        "is_completed": False,
                    }
                )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def get_all_tutorialsV2(uuid: str) -> list:
        tutorialDb: Tutorials = Database.get_table("tutorials")
        completedTutorialDB: CompletedTutorials = Database.get_table(
            "completed_tutorials"
        )
        tutorials = tutorialDb.fetch_all()
        completed = completedTutorialDB.get_user_completed(uuid)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                tutorial_list.append(
                    {
                        "id": tutorial["id"],
                        "title": tutorial["title"],
                        "markdownUrl": tutorial["markdown_url"],
                        "category": tutorial["category"],
                        "answer": tutorial[
                            "answer"
                        ],  # if tutorial['should_be_check'] else None
                        "startCode": tutorial["start_code"],
                        "shouldBeCheck": tutorial["should_be_check"],
                        "enabled": tutorial["enabled"],
                        "points": tutorial["points"],
                        "inputs": tutorial["input"],
                        "default_language": tutorial["default_language"],
                        "image": tutorial["image"],
                        "short_description": tutorial["short_description"],
                        "estimated_time": tutorial["estimated_time"],
                        "is_completed": False,
                        "path": tutorial["path"],
                    }
                )
        else:
            tutorialDb.close()
            completedTutorialDB.close()
            return []

        if completed != None and len(completed) > 0:
            for compl in completed:
                for i in range(0, len(tutorial_list)):
                    if compl["tutorial_id"] == tutorial_list[i]["id"]:
                        tutorial_list[i]["is_completed"] = True

        tutorialDb.close()
        completedTutorialDB.close()
        return tutorial_list

    @staticmethod
    def get_tutorial(id: int) -> dict:
        """
        Récupérer un tutoriel par son ID
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorial = tutorialDb.fetch(id)
        if tutorial != None:
            data = tutorial
            return {
                "id": data["id"],
                "title": data["title"],
                "markdownUrl": data["markdown_url"],
                "category": data["category"],
                "answer": data["answer"],  # if data['should_be_check'] else None
                "startCode": data["start_code"],
                "shouldBeCheck": data["should_be_check"],
                "enabled": data["enabled"],
                "points": data["points"],
                "inputs": data["input"],
                "default_language": data["default_language"],
                "image": data["image"],
                "short_description": data["short_description"],
                "estimated_time": data["estimated_time"],
                "path": data["path"],
            }
        tutorialDb.close()
        return None

    @staticmethod
    def get_tutorialV2(id: int, uuid: str) -> dict:
        tutorialDb: Tutorials = Database.get_table("tutorials")
        completedTutorialDB: CompletedTutorials = Database.get_table(
            "completed_tutorials"
        )
        tutorial = tutorialDb.fetch(id)
        if tutorial != None:
            data = tutorial
            completed = completedTutorialDB.get_user_completed(uuid)
            if completed != None and len(completed) > 0:
                for compl in completed:
                    if compl["tutorial_id"] == data["id"]:
                        return {
                            "id": data["id"],
                            "title": data["title"],
                            "markdownUrl": data["markdown_url"],
                            "category": data["category"],
                            "answer": data[
                                "answer"
                            ],  # if data['should_be_check'] else None
                            "startCode": data["start_code"],
                            "shouldBeCheck": data["should_be_check"],
                            "enabled": data["enabled"],
                            "points": data["points"],
                            "inputs": data["input"],
                            "default_language": data["default_language"],
                            "image": data["image"],
                            "short_description": data["short_description"],
                            "estimated_time": data["estimated_time"],
                            "path": data["path"],
                            "is_completed": True,
                        }
            return {
                "id": data["id"],
                "title": data["title"],
                "markdownUrl": data["markdown_url"],
                "category": data["category"],
                "answer": data["answer"],  # if data['should_be_check'] else None
                "startCode": data["start_code"],
                "shouldBeCheck": data["should_be_check"],
                "enabled": data["enabled"],
                "points": data["points"],
                "inputs": data["input"],
                "default_language": data["default_language"],
                "image": data["image"],
                "short_description": data["short_description"],
                "estimated_time": data["estimated_time"],
                "path": data["path"],
                "is_completed": False,
            }
        tutorialDb.close()
        completedTutorialDB.close()
        return None

    @staticmethod
    def create_tutorial(title: str, markdownUrl: str, startCode: str, category: str, answer: str, shouldBeCheck: bool, input: str, points: int, default_language: str, image: str, short_description: str, estimated_time: str, path: str = "js") -> bool:

        """
        Créer un tutoriel
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        result = tutorialDb.insert(title, markdownUrl, category, answer, startCode, shouldBeCheck, input, points, default_language, image, short_description, estimated_time, path)

        tutorialDb.close()
        return result

    @staticmethod
    def get_all_tutorials_by_category(category: str) -> list:
        """
        Récupérer la liste des tutoriels par leur catégorie
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorials = tutorialDb.fetch_by_category(category)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                tutorial_list.append(
                    {
                        "id": tutorial["id"],
                        "title": tutorial["title"],
                        "markdownUrl": tutorial["markdown_url"],
                        "category": tutorial["category"],
                        "answer": tutorial["answer"]
                        if tutorial["should_be_check"]
                        else None,
                        "startCode": tutorial["start_code"],
                        "shouldBeCheck": tutorial["should_be_check"],
                        "points": tutorial["points"],
                        "enabled": tutorial["enabled"],
                    }
                )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def get_all_tutorials_by_categoryV2(category: str) -> list:
        """
        Récupérer la liste des tutoriels par leur catégorie
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorials = tutorialDb.fetch_by_category(category)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                tutorial_list.append(
                    {
                        "id": tutorial["id"],
                        "title": tutorial["title"],
                        "markdownUrl": tutorial["markdown_url"],
                        "category": tutorial["category"],
                        "answer": tutorial["answer"]
                        if tutorial["should_be_check"]
                        else None,
                        "startCode": tutorial["start_code"],
                        "shouldBeCheck": tutorial["should_be_check"],
                        "points": tutorial["points"],
                        "enabled": tutorial["enabled"],
                        "inputs": tutorial["input"],
                        "default_language": tutorial["default_language"],
                        "image": tutorial["image"],
                        "short_description": tutorial["short_description"],
                        "estimated_time": tutorial["estimated_time"],
                        "path": tutorial["path"],
                        "is_completed": False,
                    }
                )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def get_all_tutorials_by_categoryV2_auth(category: str, uuid: str) -> list:
        """
        Récupérer la liste des tutoriels par leur catégorie
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        completedTutorialDB: CompletedTutorials = Database.get_table(
            "completed_tutorials"
        )
        tutorials = tutorialDb.fetch_by_category(category)
        completed = completedTutorialDB.get_user_completed(uuid)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                completed = completedTutorialDB.get_user_completed(uuid)
                if completed != None and len(completed) > 0:
                    found = False
                    for compl in completed:
                        if compl["tutorial_id"] == tutorial["id"]:
                            found = True
                            tutorial_list.append(
                                {
                                    "id": tutorial["id"],
                                    "title": tutorial["title"],
                                    "markdownUrl": tutorial["markdown_url"],
                                    "category": tutorial["category"],
                                    "answer": tutorial["answer"]
                                    if tutorial["should_be_check"]
                                    else None,
                                    "startCode": tutorial["start_code"],
                                    "shouldBeCheck": tutorial["should_be_check"],
                                    "points": tutorial["points"],
                                    "enabled": tutorial["enabled"],
                                    "inputs": tutorial["input"],
                                    "default_language": tutorial["default_language"],
                                    "image": tutorial["image"],
                                    "short_description": tutorial["short_description"],
                                    "estimated_time": tutorial["estimated_time"],
                                    "path": tutorial["path"],
                                    "is_completed": True,
                                }
                            )
                            break
                    if not found:
                        tutorial_list.append(
                            {
                                "id": tutorial["id"],
                                "title": tutorial["title"],
                                "markdownUrl": tutorial["markdown_url"],
                                "category": tutorial["category"],
                                "answer": tutorial["answer"]
                                if tutorial["should_be_check"]
                                else None,
                                "startCode": tutorial["start_code"],
                                "shouldBeCheck": tutorial["should_be_check"],
                                "points": tutorial["points"],
                                "enabled": tutorial["enabled"],
                                "inputs": tutorial["input"],
                                "default_language": tutorial["default_language"],
                                "image": tutorial["image"],
                                "short_description": tutorial["short_description"],
                                "estimated_time": tutorial["estimated_time"],
                                "path": tutorial["path"],
                                "is_completed": False,
                            }
                        )
                else:
                    tutorial_list.append(
                        {
                            "id": tutorial["id"],
                            "title": tutorial["title"],
                            "markdownUrl": tutorial["markdown_url"],
                            "category": tutorial["category"],
                            "answer": tutorial["answer"]
                            if tutorial["should_be_check"]
                            else None,
                            "startCode": tutorial["start_code"],
                            "shouldBeCheck": tutorial["should_be_check"],
                            "points": tutorial["points"],
                            "enabled": tutorial["enabled"],
                            "inputs": tutorial["input"],
                            "default_language": tutorial["default_language"],
                            "image": tutorial["image"],
                            "short_description": tutorial["short_description"],
                            "estimated_time": tutorial["estimated_time"],
                            "path": tutorial["path"],
                            "is_completed": False,
                        }
                    )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def get_all_tutorials_by_path(path: str) -> list:
        """
        Récupérer la liste des tutoriels par leur path
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorials = tutorialDb.fetch_by_path(path)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                tutorial_list.append(
                    {
                        "id": tutorial["id"],
                        "title": tutorial["title"],
                        "markdownUrl": tutorial["markdown_url"],
                        "category": tutorial["category"],
                        "answer": tutorial["answer"]
                        if tutorial["should_be_check"]
                        else None,
                        "startCode": tutorial["start_code"],
                        "shouldBeCheck": tutorial["should_be_check"],
                        "points": tutorial["points"],
                        "enabled": tutorial["enabled"],
                        "inputs": tutorial["input"],
                        "default_language": tutorial["default_language"],
                        "image": tutorial["image"],
                        "short_description": tutorial["short_description"],
                        "estimated_time": tutorial["estimated_time"],
                        "path": tutorial["path"],
                        "is_completed": False,
                    }
                )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def get_all_tutorials_by_path_auth(path: str, uuid: str) -> list:
        """
        Récupérer la liste des tutoriels par leur path
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        completedTutorialDB: CompletedTutorials = Database.get_table(
            "completed_tutorials"
        )
        tutorials = tutorialDb.fetch_by_path(path)
        # print('tutos', tutorials)
        print('len(tutorials): ', len(tutorials))
        completed = completedTutorialDB.get_user_completed(uuid)
        tutorial_list = []
        if len(tutorials) > 0:
            for tutorial in tutorials:
                # print('tutorial: ', tutorial)
                completed = completedTutorialDB.get_user_completed(uuid)
                if completed != None and len(completed) > 0:
                    found = False
                    for compl in completed:
                        if compl["tutorial_id"] == tutorial["id"]:
                            found = True
                            tutorial_list.append(
                                {
                                    "id": tutorial["id"],
                                    "title": tutorial["title"],
                                    "markdownUrl": tutorial["markdown_url"],
                                    "category": tutorial["category"],
                                    "answer": tutorial["answer"]
                                    if tutorial["should_be_check"]
                                    else None,
                                    "startCode": tutorial["start_code"],
                                    "shouldBeCheck": tutorial["should_be_check"],
                                    "points": tutorial["points"],
                                    "enabled": tutorial["enabled"],
                                    "inputs": tutorial["input"],
                                    "default_language": tutorial["default_language"],
                                    "image": tutorial["image"],
                                    "short_description": tutorial["short_description"],
                                    "estimated_time": tutorial["estimated_time"],
                                    "path": tutorial["path"],
                                    "is_completed": True,
                                }
                            )
                            break
                    if not found:
                        tutorial_list.append(
                            {
                                "id": tutorial["id"],
                                "title": tutorial["title"],
                                "markdownUrl": tutorial["markdown_url"],
                                "category": tutorial["category"],
                                "answer": tutorial["answer"]
                                if tutorial["should_be_check"]
                                else None,
                                "startCode": tutorial["start_code"],
                                "shouldBeCheck": tutorial["should_be_check"],
                                "points": tutorial["points"],
                                "enabled": tutorial["enabled"],
                                "inputs": tutorial["input"],
                                "default_language": tutorial["default_language"],
                                "image": tutorial["image"],
                                "short_description": tutorial["short_description"],
                                "estimated_time": tutorial["estimated_time"],
                                "path": tutorial["path"],
                                "is_completed": False,
                            }
                        )
                else:
                    tutorial_list.append(
                        {
                            "id": tutorial["id"],
                            "title": tutorial["title"],
                            "markdownUrl": tutorial["markdown_url"],
                            "category": tutorial["category"],
                            "answer": tutorial["answer"]
                            if tutorial["should_be_check"]
                            else None,
                            "startCode": tutorial["start_code"],
                            "shouldBeCheck": tutorial["should_be_check"],
                            "points": tutorial["points"],
                            "enabled": tutorial["enabled"],
                            "inputs": tutorial["input"],
                            "default_language": tutorial["default_language"],
                            "image": tutorial["image"],
                            "short_description": tutorial["short_description"],
                            "estimated_time": tutorial["estimated_time"],
                            "path": tutorial["path"],
                            "is_completed": False,
                        }
                    )
        else:
            tutorialDb.close()
            return []
        tutorialDb.close()
        return tutorial_list

    @staticmethod
    def update_tutorial(
        id: int,
        title: str,
        markdown_url: str,
        category: str,
        answer: str,
        start_code: str,
        should_be_check: bool,
        input: str,
        points: int,
    ) -> bool:
        """
        Modifier un tutoriel
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        result = tutorialDb.update(
            id,
            title,
            markdown_url,
            category,
            answer,
            start_code,
            should_be_check,
            input,
            points,
        )
        tutorialDb.close()
        return result

    @staticmethod
    def toggle_tutorial(id: int, updated: bool) -> dict:
        """
        @deprecated

        Activer ou désactiver un tutoriel
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        result = tutorialDb.update_enabled(id, updated)
        if result:
            tutorialDb.close()
            return {"id": id, "enabled": updated}
        tutorialDb.close()
        return None

    @staticmethod
    def get_all_categories() -> list:
        """
        Récupérer la liste des catégories
        """
        categoryDb: Category = Database.get_table("category")
        result = categoryDb.fetch_all_categories()
        returning = []
        for cat_list in result:
            returning.append(
                {
                    "name": cat_list["name"],
                    "description": cat_list["description"],
                    "image": cat_list["image_url"],
                }
            )
        categoryDb.close()
        return returning

    @staticmethod
    def create_path(name: str) -> bool:
        """
        Créer un nouveau path pour les tutoriels
        """
        pathDB: Paths = Database.get_table("path")
        result = pathDB.insert(name)
        pathDB.close()
        return result

    @staticmethod
    def create_category(name: str, description: str, image_url: str) -> bool:
        """
        Créer une nouvelle catégorie de tutoriel
        """
        categoryDb: Category = Database.get_table("category")
        result = categoryDb.create_category(name, description, image_url)
        categoryDb.close()
        return result

    @staticmethod
    def update_path(new_name: str, id: int) -> bool:
        """
        Modifier un path
        """
        pathDB: Paths = Database.get_table("path")
        result = pathDB.update(id, new_name)
        pathDB.close()
        return result

    @staticmethod
    def delete_path(id: int) -> bool:
        """
        Supprimer un path
        """
        pathDB: Paths = Database.get_table("path")
        result = pathDB.delete(id)
        pathDB.close()
        return result

    @staticmethod
    def get_paths() -> list:
        """
        Récupérer la liste des paths
        """
        pathDB: Paths = Database.get_table("path")
        result = pathDB.fetch_all()
        returning = []
        for path_list in result:
            returning.append({"id": path_list["id"], "path": path_list["path"]})
        pathDB.close()
        return returning

    @staticmethod
    def get_path(id: int) -> dict:
        """
        Récupérer un path par son ID
        """
        pathDB: Paths = Database.get_table("path")
        result = pathDB.fetch(id)
        pathDB.close()
        return result

    @staticmethod
    def update_category(name: str, description: str, image_url: str) -> bool:
        """
        Modifier une catégorie
        """
        categoryDb: Category = Database.get_table("category")
        result = categoryDb.update_category(name, description, image_url)
        categoryDb.close()
        return result

    @staticmethod
    def delete_category(name: str) -> bool:
        """
        Supprimer une catégorie
        """
        categoryDb: Category = Database.get_table("category")
        result = categoryDb.delete_category(name)
        categoryDb.close()
        return result

    @staticmethod
    def validate_tutorial(
        uuid: str, tutorial_id: int, language: str, characters: int, lines: int
    ) -> int:
        """
        Valider un tutoriel
        """
        userTutorialScoreDb: UserTutorialScore = Database().get_table(
            "user_tutorial_score"
        )
        total_completions = userTutorialScoreDb.fetch(uuid, tutorial_id, language)
        tutorial_completedDB: CompletedTutorials = Database().get_table(
            "completed_tutorials"
        )
        if total_completions == None:
            total_completions = 1
        else:
            total_completions = total_completions["total_completions"]
            total_completions += 1

        tutorial_completedDB.insert(uuid, tutorial_id)

        if total_completions == 1:
            accountDb: AccountDatabase = Database().get_table("account")
            tutorialDb: Tutorials = Database().get_table("tutorials")
            tuto_details = tutorialDb.fetch(tutorial_id)
            result = userTutorialScoreDb.insert(
                uuid, tutorial_id, language, characters, lines
            )
            user = accountDb.fetch(uuid)
            accountDb.update_points(uuid, user["points"] + tuto_details["points"])
            accountDb.close()
            tutorialDb.close()
            if result:
                userTutorialScoreDb.close()
                return 1
            userTutorialScoreDb.close()
            return 0
        else:
            result = userTutorialScoreDb.update(
                uuid, tutorial_id, total_completions, language, characters, lines
            )
            userTutorialScoreDb.close()
            return result["total_completions"]

    @staticmethod
    def get_scoreboard_tutorial_id(tutorial_id: int) -> list:
        """
        Récupérer le scoreboard d'un tutoriel par son ID
        """
        userTutorialScoreDb: UserTutorialScore = Database.get_table(
            "user_tutorial_score"
        )
        scoreboard_tutorial_list = userTutorialScoreDb.fetch_all_score_of_tutorial(
            tutorial_id
        )
        scoreboard_tutorial_list.sort(key=lambda obj: obj["characters"], reverse=True)

        for i in range(0, len(scoreboard_tutorial_list)):
            uuid = scoreboard_tutorial_list[i].get("uuid")
            tmp = userTutorialScoreDb.fetch(uuid, tutorial_id)
            scoreboard_tutorial_list[i]["total_completions"] = tmp.get(
                "total_completions"
            )
        userTutorialScoreDb.close()
        return scoreboard_tutorial_list

    @staticmethod
    def get_percentage_tutorial_id(tutorial_id: int) -> float:
        """
        Récupérer le pourcentage de complétion du tutoriel
        """
        userTutorialScoreDb: UserTutorialScore = Database.get_table(
            "user_tutorial_score"
        )
        accountDb: AccountDatabase = Database.get_table("account")
        total_completions = len(
            userTutorialScoreDb.fetch_all_score_of_tutorial(tutorial_id)
        )
        total_users = len(accountDb.fetchall())
        userTutorialScoreDb.close()
        accountDb.close()
        return (total_completions / total_users) * 100

    @staticmethod
    def get_user_scoreboard(uuid: str) -> list:
        """
        Récupérer le scoreboard de l'utilisateur
        """
        userTutorialScoreDb: UserTutorialScore = Database.get_table(
            "user_tutorial_score"
        )
        scores = userTutorialScoreDb.fetch_all_score_of_user(uuid)
        userTutorialScoreDb.close()
        return scores

    @staticmethod
    def get_user_success(uuid: str) -> list:
        """
        Récupérer le scoreboard de l'utilisateur
        """
        userTutorialScoreDb: UserTutorialScore = Database.get_table(
            "user_tutorial_score"
        )
        success = userTutorialScoreDb.fetch_all_score_of_user(uuid)
        userTutorialScoreDb.close()
        return success

    @staticmethod
    def get_total_number_tutorials() -> int:
        """
        Récupérer le nombre total de tutoriels sur le serveur
        """
        tutorialDb: Tutorials = Database.get_table("tutorials")
        tutorials = tutorialDb.fetch_all()
        tutorialDb.close()
        return len(tutorials)

    @staticmethod
    def get_user_completed_tutorials() -> list:
        pass

    @staticmethod
    def get_user_last_10_completed_tutorials() -> list:
        pass

    @staticmethod
    def get_markdown_list() -> Dict[bool, list]:
        """
        Récupérer la liste des markdowns disponibles sur Github
        """
        headers = {
            "Authorization": f"Bearer {os.getenv('GITHUB_API_TOKEN')}",
            "Content-Type": "application/json",
        }
        try:
            r = requests.get(
                "https://api.github.com/repos/Block2School/tutorials/contents/en",
                headers=headers,
            )
            r = r.json()
            markdowns = []
            for i in range(0, len(r)):
                if r[i]["name"].endswith(".md"):
                    markdowns.append(
                        {
                            "title": r[i]["name"].replace(".md", ""),
                            "markdown_url": r[i]["download_url"],
                        }
                    )
            return {"success": True, "markdowns": markdowns}
        except Exception as e:
            print(f"error: {e}")
            return {"success": False, "markdowns": []}

    @staticmethod
    def create_markdown(filename: str, content: str) -> Dict[bool, str]:
        """
        Créer un markdown sur Github
        """
        headers = {
            "Authorization": f"Bearer {os.getenv('GITHUB_API_TOKEN')}",
            "Content-Type": "application/json",
        }
        data = {
            "message": f"Adding {filename}.md to the repository",
            "content": str(base64.b64encode(content.encode("ascii")).decode("ascii")),
        }
        try:
            r = requests.put(
                f"https://api.github.com/repos/Block2School/tutorials/contents/en/{filename}.md",
                data=json.dumps(data),
                headers=headers,
            )
            r = r.json()
            return {"success": True, "url": r["content"]["download_url"]}
        except Exception as e:
            print(f"error: {e}")
            return {"success": False}