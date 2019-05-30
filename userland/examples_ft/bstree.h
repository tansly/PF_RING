/*
    Generic AVL tree implementation in C
    Copyright (C) 2017 Yağmur Oymak, Berk Özkütük

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef BSTREE_H
#define BSTREE_H

/* Some notes:
 ** No duplicate keys will be present in the tree, inserting an already
 * existing value will increase the count held at the node. Functions that have
 * "cnt" as a suffix in their names operate considering the count at the
 * found node, with details explained for each of them below.
 */

struct bstree;

struct bstree *bstree_new(
        int (*compare_object)(const void *lhs, const void *rhs),
        void (*free_object)(void *object));

/* Inserts the given object to the tree. If the object already exists,
 * increment the count.
 */
void bstree_insert(struct bstree *tree, void *object);

/* Like insert, but instead of incrementing the count for an already existing
 * object, it gets rid of the old object, replaces it with the given one.
 */
void bstree_replace(struct bstree *tree, void *object);

/* Destroy everything, ggwp.
 */
void bstree_destroy(struct bstree *tree);

/* Traverse (in-order) the tree with a given operation, optionally accumulating
 * data in it_data. 'operation' must point to a valid function.
 * Usage of it_data is up to the operation function given by the user.
 * It is not used anywhere by us.
 * Traversal is stopped when the operation returns true.
 * Returns true if traversal is stopped by the operation function,
 * else false (traversal is finished by visiting all nodes).
 */
int bstree_traverse_inorder(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Traverse (pre-order) the tree with a given operation, optionally
 * accumulating data in it_data. 'operation' must point to a valid function.
 * Usage of it_data is up to the operation function given by the user.
 * It is not used anywhere by us.
 * Traversal is stopped when the operation returns true.
 * Returns true if traversal is stopped by the operation function,
 * else false (traversal is finished by visiting all nodes).
 */
int bstree_traverse_preorder(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Traverse (post-order) the tree with a given operation, optionally
 * accumulating data in it_data. 'operation' must point to a valid function.
 * Usage of it_data is up to the operation function given by the user.
 * It is not used anywhere by us.
 * Traversal is stopped when the operation returns true.
 * Returns true if traversal is stopped by the operation function,
 * else false (traversal is finished by visiting all nodes).
 */
int bstree_traverse_postorder(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Traverse (in-order) the tree in a similar fashion, but apply the operation
 * 'count' times * for each object, 'count' being the count of the object held
 * in the tree.
 */
int bstree_traverse_inorder_cnt(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Traverse (pre-order) the tree in a similar fashion, but apply the operation
 * 'count' times for each object, 'count' being the count of the object held
 * in the tree.
 */
int bstree_traverse_preorder_cnt(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Traverse (post-order) the tree in a similar fashion, but apply the operation
 * 'count' times for each object, 'count' being the count of the object held
 * in the tree.
 */
int bstree_traverse_postorder_cnt(const struct bstree *tree, void *it_data,
        int (*operation)(void *object, void *it_data));

/* Return the count of the given key.
 */
int bstree_count(const struct bstree *tree, const void *key);

/* Return the pointer to the object matching the given key.
 */
void *bstree_search(const struct bstree *tree, const void *key);

/* Finds and removes the node matching the given key and frees the object.
 * Does nothing if the given key is not found in the tree.
 */
void bstree_remove(struct bstree *tree, const void *key);

/* Finds and removes the node matching the given key but does not free
 * the object. Does nothing if the given key is not found in the tree.
 */
void bstree_release(struct bstree *tree, const void *key);

/* Return the number of nodes in the tree.
 */
int bstree_size(struct bstree *tree);

/* Return the length of the longest path from the root to a leaf.
 * Empty tree has height -1, a tree consisting of a single node has height 0.
 */
int bstree_height(struct bstree *tree);

#endif
